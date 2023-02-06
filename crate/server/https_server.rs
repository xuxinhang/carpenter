use std::rc::Rc;
use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, Shutdown};
use std::str::FromStr;
use mio::{Interest, Token};
use mio::event::{Event};
use mio::net::{TcpListener, TcpStream};
use rustls::{ServerConfig, ServerConnection};
use crate::event_loop::{EventHandler, EventLoop, EventRegistryIntf};
use crate::transformer::{certstorage::get_cert_data_by_hostname};
use crate::transformer::{create_transformer_unit, TransformerUnit, TransformerUnitError, TransformerUnitResult};
use super::ProxyServer;
use super::prepare::prepare_proxy_client_to_remote_host;
use crate::proxy_client::{ProxyClientReadyCall};
use crate::common::HostAddr;


struct TunnelMeta {
    _remote_host: HostAddr,
    http_tunnel_mode: bool,
}

pub struct ProxyServerHttpOverTls {
    listener_socket: TcpListener,
    listener_token: Token,
}

impl ProxyServerHttpOverTls {
    pub fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let listener_socket = TcpListener::bind(addr)?;
        Ok(Self {
            listener_socket,
            listener_token: Token(0),
        })
    }
}

impl ProxyServer for ProxyServerHttpOverTls {
    fn launch(mut self, event_loop: &mut EventLoop) -> std::io::Result<()> {
        self.listener_token = event_loop.token.get();
        event_loop.register(Box::new(self))
    }
}

impl EventHandler for ProxyServerHttpOverTls {
    fn register(&mut self, registry: &mut EventRegistryIntf) ->std::io::Result<()> {
        registry.register(&mut self.listener_socket, self.listener_token, Interest::READABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) ->std::io::Result<()> {
        registry.reregister(&mut self.listener_socket, self.listener_token, Interest::READABLE)
    }

    fn handle(self: Box<Self>, _evt: &Event, event_loop: &mut EventLoop) {
        let x = self.listener_socket.accept();
        if let Err(e) = x {
            wd_log::log_warn_ln!("ProxyServerHttpOverTls | listener_socket.accpet {:?}", e);
            return;
        }

        let (conn, _) = x.unwrap();
        let conn_token = event_loop.token.get();
        let tunnel = Box::new(
            ShakingConnection::new(conn, conn_token, "localhost".parse().unwrap()));
        event_loop.register(tunnel).unwrap();

        // do not forget to receive the further connection
        event_loop.reregister(self).unwrap();
    }
}


pub fn parse_http_proxy_message(msg_buf: &[u8]) -> Result<(usize, HostAddr, bool), String> {
    use crate::utils::http_message::parse_http_header;
    let r = parse_http_header(msg_buf);
    if r.is_none() {
        return Err("Invalid http message".to_string());
    }
    let (msg_header_length, msg_header_map) = r.unwrap();
    let use_http_tunnel_mode = msg_header_map[":method"].as_str() == "CONNECT";
    let host_str: &str = if use_http_tunnel_mode {
        &msg_header_map[":path"]
    } else {
        let path_str = &msg_header_map[":path"];
        let scheme_prefix = "http://";
        let pos_l = path_str.find(scheme_prefix);
        if pos_l.is_none() {
            return Err(format!("Invalid request path, only http supported: {:?}", path_str));
        }
        let pos_l = pos_l.unwrap() + scheme_prefix.len();
        let pos_r = &path_str[pos_l..].find("/").unwrap_or(path_str.len() - pos_l) + pos_l;
        &path_str[pos_l..pos_r]
    };

    // Get hostname from the string
    let r = HostAddr::from_str(host_str);
    if r.is_err() {
        return Err(format!("Invalid host {}", host_str));
    }
    let remote_host = r.unwrap();

    Ok((msg_header_length, remote_host, use_http_tunnel_mode))
}


struct ShakingConnection {
    conn: TcpStream,
    conn_token: Token,
    conn_rsta: ConnStatus,
    conn_wsta: ConnStatus,
    tls: rustls::ServerConnection,
    received_text: Vec<u8>,
}

impl ShakingConnection {
    fn new(conn: TcpStream, conn_token: Token, _host: HostAddr) -> Self {
        let (local_tls_cert_data, local_tls_pkey_data) =
            get_cert_data_by_hostname(Some(_host.host())).unwrap();
        let local_tls_conf = std::sync::Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(local_tls_cert_data, local_tls_pkey_data)
                .expect("bad local_tls_conf")
        );
        let local_tls = ServerConnection::new(local_tls_conf).unwrap();
        Self {
            conn,
            conn_token,
            tls: local_tls,
            received_text: Vec::with_capacity(1024),
            // transmitting_text: Vec::with_capacity(512),
            conn_rsta: ConnStatus::Available,
            conn_wsta: ConnStatus::Available,
        }
    }
}

impl EventHandler for ShakingConnection {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.conn, self.conn_token, Interest::READABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let interest = if self.conn_rsta == ConnStatus::Block && self.conn_wsta == ConnStatus::Block {
            Interest::READABLE | Interest::WRITABLE
        } else if self.conn_wsta == ConnStatus::Block {
            Interest::WRITABLE
        } else if self.conn_rsta == ConnStatus::Block {
            Interest::READABLE
        } else {
            Interest::READABLE
        };
        registry.reregister(&mut self.conn, self.conn_token, interest)
    }

    fn handle(mut self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        let shutdown_conn = |c: &mut TcpStream| {
            let x = c.shutdown(Shutdown::Both);
            if let Err(e) = x {
                wd_log::log_warn_ln!("Fail to shutdown local conn {}", e);
            }
        };

        if event.is_readable() {
            self.conn_rsta = ConnStatus::Available;
        }
        if event.is_writable() {
            self.conn_wsta = ConnStatus::Available;
        }

        let conn = &mut self.conn;
        let tls = &mut self.tls;

        loop {
            let mut transfer_size = 0;

            while tls.wants_read() && self.conn_rsta == ConnStatus::Available {
                match tls.read_tls(conn) {
                    Err(ref e) if would_block(e) => {
                        self.conn_rsta = ConnStatus::Block;
                        break;
                    }
                    Err(ref e) => {
                        wd_log::log_error_ln!("ShakingConnection # Io Error {:?}", e);
                        shutdown_conn(conn);
                        return;
                    }
                    Ok(0) => {
                        wd_log::log_warn_ln!("ShakingConnection # connection closed");
                        shutdown_conn(conn);
                        return;
                    }
                    Ok(s) => {
                        transfer_size += s;
                    }
                }
                if let Err(e) = tls.process_new_packets() {
                    wd_log::log_error_ln!("ShakingConnection # Tls Error {:?}", e);
                    shutdown_conn(conn);
                    return;
                }
            }

            loop {
                let mut buf: [u8; 32*1024] = [0; 32*1024];
                match tls.reader().read(&mut buf) {
                    Err(ref e) if would_block(e) => {
                        break;
                    }
                    Err(ref e) => {
                        wd_log::log_error_ln!("ShakingConnection # reader {:?}", e);
                        shutdown_conn(conn);
                        return;
                    }
                    Ok(0) => {
                        wd_log::log_warn_ln!("ShakingConnection # tls closed");
                        shutdown_conn(conn);
                        return;
                    }
                    Ok(s) => {
                        self.received_text.write(&buf[..s]).unwrap();
                        transfer_size += s;
                    }
                }
            }

            while tls.wants_write() && self.conn_wsta == ConnStatus::Available {
                match tls.write_tls(conn) {
                    Err(ref e) if would_block(e) => {
                        self.conn_wsta = ConnStatus::Block;
                        break;
                    }
                    Err(ref e) => {
                        wd_log::log_error_ln!("ShakingConnection # Error {:?}", e);
                        shutdown_conn(conn);
                        return;
                    }
                    Ok(s) => {
                        transfer_size += s;
                    }
                }
            }

            // write no plain text to tls layer

            if transfer_size == 0 { break; }
        }

        loop {
            let x = parse_http_proxy_message(self.received_text.as_slice());
            if let Err(_e) = x {
                break;
            }
            let (_msg_header_length, host, use_http_tunnel_mode) = x.unwrap();
            // println!("shaked {:?} {:?}", host, use_http_tunnel_mode);

            let tunnel_meta = TunnelMeta {
                _remote_host: host.clone(),
                http_tunnel_mode: use_http_tunnel_mode,
            };
            let transformer = create_transformer_unit(&host, use_http_tunnel_mode).unwrap();
            let proxy_client_callback = ProxyServerResponseHandler {
                conn: self.conn,
                conn_token: self.conn_token,
                tls: self.tls,
                transformer,
                meta: tunnel_meta,
                peer_conn: None,
                peer_token: None,
            };
            prepare_proxy_client_to_remote_host(host.clone(), event_loop, Box::new(proxy_client_callback));
            return;
        }

        assert!(self.conn_rsta == ConnStatus::Block || self.conn_wsta == ConnStatus::Block);
        event_loop.reregister(self).unwrap();
    }
}


struct ProxyServerResponseHandler {
    conn: TcpStream,
    conn_token: Token,
    tls: ServerConnection,
    transformer: Box<dyn TransformerUnit>,
    meta: TunnelMeta,
    peer_conn: Option<TcpStream>,
    peer_token: Option<Token>,
}

impl ProxyClientReadyCall for ProxyServerResponseHandler {
    fn proxy_client_ready(
        mut self: Box<Self>,
        event_loop: &mut EventLoop,
        peer_source: TcpStream,
        peer_token: Token,
    ) -> std::io::Result<()> {
        self.peer_conn = Some(peer_source);
        self.peer_token = Some(peer_token);
        event_loop.reregister(Box::new(*self)).unwrap();
        Ok(())
    }
}

impl EventHandler for ProxyServerResponseHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.conn, self.conn_token, Interest::WRITABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.reregister(&mut self.conn, self.conn_token, Interest::WRITABLE)
    }

    fn handle(mut self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_writable() {
            if self.meta.http_tunnel_mode {
                let tls = &mut self.tls;
                let conn = &mut self.conn;
                let message = "HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes();
                tls.writer().write(&message).unwrap();
                if let Err(e) = tls.write_tls(conn) {
                    wd_log::log_warn_ln!("ProxyServerResponseHandler # write_tls {:?}", e);
                    return;
                }
            }

            let mut tunnel_transformers = Vec::new();
            tunnel_transformers.push(self.transformer);
            tunnel_transformers.insert(0, Box::new(ServerFerryTransformer {
                tls: self.tls,
                has_closed: false,
            }));

            let tunnel_cell = Rc::new(RefCell::new(EstablishedTunnel::new(
                tunnel_transformers,
                self.meta,
                self.conn,
                self.conn_token,
                self.peer_conn.unwrap(),
                self.peer_token.unwrap(),
            )));

            EstablishedTunnel::process_conn_event(tunnel_cell, event_loop, None, None);
        }
    }
}


#[inline(always)]
fn would_block(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::WouldBlock
}

#[inline(always)]
fn connection_error(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::ConnectionAborted => true,
        ErrorKind::ConnectionReset => true,
        _ => false,
    }
}

struct EstablishedTunnel {
    transformers: Vec<Box<dyn TransformerUnit>>,
    _meta: TunnelMeta,
    //
    local_conn: TcpStream,
    local_token: Token,
    local_wsta: ConnStatus,
    local_rsta: ConnStatus,
    //
    remote_conn: TcpStream,
    remote_token: Token,
    remote_wsta: ConnStatus,
    remote_rsta: ConnStatus,
    //
    transmit_buffers: Vec<(Vec<u8>, Interest)>,
    receive_buffers: Vec<(Vec<u8>, Interest)>,
}

#[derive(PartialEq, Eq, Debug)]
enum ConnStatus { Available, Block, Shutdown, Error }

impl EstablishedTunnel {
    fn new(
        transformers: Vec<Box<dyn TransformerUnit>>,
        meta: TunnelMeta,
        local_conn: TcpStream,
        local_token: Token,
        remote_conn: TcpStream,
        remote_token: Token,
    ) -> Self {
        let tf_number = transformers.len();
        let mut transmit_buffers = Vec::with_capacity(tf_number+1);
        let mut receive_buffers = Vec::with_capacity(tf_number+1);
        let default_interest = Interest::READABLE | Interest::WRITABLE;
        for _ in 0..(tf_number+1) {
            transmit_buffers.push((Vec::with_capacity(32 * 1024), default_interest.clone()));
            receive_buffers.push((Vec::with_capacity(32 * 1024), default_interest.clone()));
        }

        Self {
            transformers,
            _meta: meta,
            local_token,
            local_conn,
            local_wsta: ConnStatus::Available,
            local_rsta: ConnStatus::Available,
            remote_token,
            remote_conn,
            remote_wsta: ConnStatus::Available,
            remote_rsta: ConnStatus::Available,
            transmit_buffers,
            receive_buffers,
        }
    }

    fn crash_tunnel(&mut self) {
        // wd_log::log_warn_ln!("Tunnel is crashing due to the unrecoverable error.");
        let r = self.local_conn.shutdown(std::net::Shutdown::Both);
        if let Err(e) = r {
            wd_log::log_warn_ln!("Fail to shutdown local conn {}", e);
        }
        let r = self.remote_conn.shutdown(std::net::Shutdown::Both);
        if let Err(e) = r {
            wd_log::log_warn_ln!("Fail to shutdown remote conn {}", e);
        }
        // TODO: unregister handler
    }

    fn do_transfer(&mut self) {
        use std::iter::zip;
        let tf_number = self.transformers.len();

        loop {
            let mut transfer_count = 0;

            // fill buffers on transmit path
            for _ in 0..8 {
                let mut xfer_count = 0;
                // read from: local_conn
                {
                    let bf = &mut self.transmit_buffers.first_mut().unwrap();
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_readable() && buf.len() == 0 && self.local_rsta == ConnStatus::Available {
                        buf.resize(buf.capacity(), 0);
                        match self.local_conn.read(buf.as_mut_slice()) {
                            Ok(0) => {
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                                self.local_rsta = ConnStatus::Shutdown;
                            }
                            Ok(s) => {
                                wd_log::log_debug_ln!("Tunnel # local conn read {}", s);
                                self.local_rsta = ConnStatus::Available;
                                buf.resize(s, 0);
                                xfer_count += s;
                            }
                            Err(ref e) if would_block(e) => {
                                buf.resize(0, 0);
                                self.local_rsta = ConnStatus::Block;
                            }
                            Err(ref e) if connection_error(e) => {
                                wd_log::log_debug_ln!("Connection Error {:?}", e);
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                                self.local_rsta = ConnStatus::Shutdown;
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Connection Error {:?}", e);
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                                self.local_rsta = ConnStatus::Error;
                            }
                        }
                    }
                }
                // read from: transformer units
                assert_eq!(self.transmit_buffers.iter().count(), tf_number+1);
                for (bf, tf) in zip(
                    self.transmit_buffers.iter_mut().skip(1),
                    self.transformers.iter_mut()
                ) {
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_readable() && buf.len() == 0 {
                        buf.resize(buf.capacity(), 0);
                        match tf.transmit_read(buf.as_mut_slice()) {
                            Ok(s) => {
                                buf.resize(s, 0);
                                xfer_count += s;
                            }
                            Err(TransformerUnitError::IoError(ref e)) if would_block(e) => {
                                buf.resize(0, 0);
                            }
                            Err(TransformerUnitError::ClosedError()) => {
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Transform Error R {:?}", e);
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                            }
                        }
                    }
                }

                transfer_count += xfer_count;
                if xfer_count == 0 { break; }
            }

            // output buffers on transmit path
            for _ in 0..8 {
                let mut xfer_count = 0;
                // write into: transformer units
                for (bf, tf) in zip(
                    self.transmit_buffers.iter_mut().take(tf_number),
                    self.transformers.iter_mut()
                ) {
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_writable() && buf.len() > 0 {
                        match tf.transmit_write(buf.as_slice()) {
                            Ok(s) => {
                                buf.drain(0..s);
                                xfer_count += s;
                            }
                            Err(TransformerUnitError::IoError(ref e)) if would_block(e) => {
                                buf.drain(0..0);
                            }
                            Err(TransformerUnitError::ClosedError()) => {
                                sta.remove(Interest::WRITABLE);
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Transform Error W {:?}", e);
                                sta.remove(Interest::WRITABLE);
                            }
                        }
                    }
                    if !sta.is_writable() {
                        buf.clear();
                    }
                }
                // write into: remote connection
                {
                    let bf = self.transmit_buffers.last_mut().unwrap();
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_writable() && buf.len() > 0 && self.remote_wsta == ConnStatus::Available {
                        match self.remote_conn.write(buf.as_slice()) {
                            Ok(s) => {
                                buf.drain(0..s);
                                xfer_count += s;
                                wd_log::log_debug_ln!("Tunnel # remote conn write {}", s);
                            }
                            Err(ref e) if would_block(e) => {
                                self.remote_wsta = ConnStatus::Block;
                            }
                            Err(ref e) if connection_error(e) => {
                                wd_log::log_debug_ln!("Connection Error {:?}", e);
                                sta.remove(Interest::WRITABLE);
                                self.remote_wsta = ConnStatus::Shutdown;
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Connection Error {:?}", e);
                                sta.remove(Interest::WRITABLE);
                                self.remote_wsta = ConnStatus::Error;
                            }
                        }
                    }
                    if !sta.is_writable() {
                        buf.clear();
                    }
                }

                transfer_count += xfer_count;
                if xfer_count == 0 { break; }
            }

            // fill buffers on receive path
            for _ in 0..8 {
                let mut xfer_count = 0;
                // read from: remote_conn
                {
                    let bf = &mut self.receive_buffers.last_mut().unwrap();
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_readable() && buf.len() == 0 && self.remote_rsta == ConnStatus::Available {
                        buf.resize(buf.capacity(), 0);
                        match self.remote_conn.read(buf.as_mut_slice()) {
                            Ok(0) => {
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                                self.remote_rsta = ConnStatus::Shutdown;
                            }
                            Ok(s) => {
                                buf.resize(s, 0);
                                xfer_count += s;
                                wd_log::log_debug_ln!("Tunnel # remote conn read {}", s);
                            }
                            Err(ref e) if would_block(e) => {
                                buf.resize(0, 0);
                                self.remote_rsta = ConnStatus::Block;
                            }
                            Err(ref e) if connection_error(e) => {
                                wd_log::log_debug_ln!("Connection Error {:?}", e);
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                                self.remote_rsta = ConnStatus::Shutdown;
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Connection Error {:?}", e);
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                                self.remote_rsta = ConnStatus::Error;
                            }
                        }
                    }
                }
                // read from: transformer units
                for (bf, tf) in zip(
                    self.receive_buffers.iter_mut().take(tf_number),
                    self.transformers.iter_mut()
                ) {
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_readable() && buf.len() == 0 {
                        buf.resize(buf.capacity(), 0);
                        match tf.receive_read(buf.as_mut_slice()) {
                            Ok(s) => {
                                buf.resize(s, 0);
                                xfer_count += s;
                            }
                            Err(TransformerUnitError::IoError(ref e)) if would_block(e) => {
                                buf.resize(0, 0);
                            }
                            Err(TransformerUnitError::ClosedError()) => {
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Tunnel # Transform Error RR {:?}", e);
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                            }
                        }
                    }
                }

                transfer_count += xfer_count;
                if xfer_count == 0 { break; }
            }

            // output buffers on receive path
            for _ in 0..8 {
                let mut xfer_count = 0;
                // write into: transformer units
                for (bf, tf) in zip(
                    self.receive_buffers.iter_mut().skip(1),
                    self.transformers.iter_mut()
                ) {
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_writable() && buf.len() > 0 {
                        match tf.receive_write(buf.as_slice()) {
                            Ok(s) => {
                                buf.drain(0..s);
                                xfer_count += s;
                            }
                            Err(TransformerUnitError::IoError(ref e)) if would_block(e) => {
                                buf.drain(0..0);
                            }
                            Err(TransformerUnitError::ClosedError()) => {
                                sta.remove(Interest::WRITABLE);
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Tunnel # Transform Error W {:?}", e);
                                sta.remove(Interest::WRITABLE);
                            }
                        }
                    }
                    if !sta.is_writable() {
                        buf.clear();
                    }
                }
                // write into: local connection
                {
                    let bf = self.receive_buffers.first_mut().unwrap();
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_writable() && buf.len() > 0 && self.local_wsta == ConnStatus::Available {
                        match self.local_conn.write(buf.as_slice()) {
                            Ok(s) => {
                                buf.drain(0..s);
                                xfer_count += s;
                                wd_log::log_debug_ln!("Tunnel # local conn write {}", s);
                            }
                            Err(ref e) if would_block(e) => {
                                self.local_wsta = ConnStatus::Block;
                            }
                            Err(ref e) if connection_error(e) => {
                                wd_log::log_debug_ln!("Tunnel # Connection Error {:?}", e);
                                sta.remove(Interest::WRITABLE);
                                self.local_wsta = ConnStatus::Shutdown;
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Tunnel # Connection Error {:?}", e);
                                sta.remove(Interest::WRITABLE);
                                self.local_wsta = ConnStatus::Error;
                            }
                        }
                    }
                    if !sta.is_writable() {
                        buf.clear();
                    }
                }

                transfer_count += xfer_count;
                if xfer_count == 0 { break; }
            }

            if transfer_count == 0 { break; }
        }
    }

    fn process_conn_event(
        tunnel_cell: Rc<RefCell<EstablishedTunnel>>,
        event_loop: &mut EventLoop,
        local_conn_event: Option<&Event>,
        remote_conn_event: Option<&Event>,
    ) {
        let mut tunnel_borrow = tunnel_cell.borrow_mut();
        let tunnel = &mut * tunnel_borrow;

        let set_status_by_event = |e: &Event, wsta: &mut ConnStatus, rsta: &mut ConnStatus| {
            if e.is_readable() { *rsta = ConnStatus::Available; }
            if e.is_writable() { *wsta = ConnStatus::Available; }
        };

        if let Some(e) = local_conn_event {
            set_status_by_event(e, &mut tunnel.local_wsta, &mut tunnel.local_rsta);
        }
        if let Some(e) = remote_conn_event {
            set_status_by_event(e, &mut tunnel.remote_wsta, &mut tunnel.remote_rsta);
        }

        tunnel.do_transfer();

        if tunnel.remote_rsta == ConnStatus::Error || tunnel.remote_wsta == ConnStatus::Error ||
            tunnel.local_rsta == ConnStatus::Error || tunnel.local_wsta == ConnStatus::Error
        {
            tunnel.crash_tunnel();
            return;
        }

        let get_interest_by_status = |wsta: &ConnStatus, rsta: &ConnStatus| {
            if *wsta == ConnStatus::Block && *rsta == ConnStatus::Block {
                Some(Interest::WRITABLE | Interest::READABLE)
            } else if *wsta == ConnStatus::Block {
                Some(Interest::WRITABLE)
            } else if *rsta == ConnStatus::Block {
                Some(Interest::READABLE)
            } else {
                None
            }
        };

        drop(tunnel);
        drop(tunnel_borrow);

        let tunnel = tunnel_cell.borrow();
        let local_interest = get_interest_by_status(&tunnel.local_wsta, &tunnel.local_rsta);
        let remote_interest = get_interest_by_status(&tunnel.remote_wsta, &tunnel.remote_rsta);
        drop(tunnel);

        if let Some(i) = local_interest {
            event_loop.reregister(Box::new(EstablishedTunnelLocalConnHandler {
                tunnel: tunnel_cell.clone(),
                interest: i,
            })).unwrap();
        }
        if let Some(i) = remote_interest {
            event_loop.reregister(Box::new(EstablishedTunnelRemoteConnHandler {
                tunnel: tunnel_cell.clone(),
                interest: i,
            })).unwrap();
        }
    }
}


struct ServerFerryTransformer {
    tls: ServerConnection,
    has_closed: bool,
}

impl TransformerUnit for ServerFerryTransformer {
    fn transmit_write(&mut self, mut buf: &[u8]) -> TransformerUnitResult {
        if !self.tls.wants_read() {
            return Ok(0);
        }
        let s = self.tls.read_tls(&mut buf).map_err(|e| TransformerUnitError::IoError(e))?;
        if s == 0 {
            return Ok(s);
        }
        if s == 0 && self.has_closed {
            return Err(TransformerUnitError::ClosedError());
        }

        let state = self.tls.process_new_packets().map_err(|e| TransformerUnitError::TlsError(e))?;
        let _plaintext_size = state.plaintext_bytes_to_read();
        let peer_closed = state.peer_has_closed();

        if peer_closed {
            self.has_closed = true;
        }
        return Ok(s);
    }

    fn transmit_read(&mut self, buf: &mut [u8]) -> TransformerUnitResult {
        let s = self.tls.reader().read(buf).map_err(|e| TransformerUnitError::IoError(e))?;
        if s == 0 && self.has_closed {
            Err(TransformerUnitError::ClosedError())
        } else {
            Ok(s)
        }
    }

    fn transmit_end(&mut self) -> TransformerUnitResult {
        self.tls.send_close_notify();
        self.has_closed = true;
        Ok(0)
    }

    fn receive_write(&mut self, buf: &[u8]) -> TransformerUnitResult {
        let s = self.tls.writer().write(buf).map_err(|e| TransformerUnitError::IoError(e))?;
        if s == 0 && self.has_closed {
            Err(TransformerUnitError::ClosedError())
        } else {
            Ok(s)
        }
    }

    fn receive_read(&mut self, mut buf: &mut [u8]) -> TransformerUnitResult {
        let s = self.tls.write_tls(&mut buf).map_err(|e| TransformerUnitError::IoError(e))?;
        if s == 0 && self.has_closed {
            Err(TransformerUnitError::ClosedError())
        } else {
            Ok(s)
        }
    }

    fn receive_end(&mut self) ->TransformerUnitResult {
        self.tls.send_close_notify();
        self.has_closed = true;
        Ok(0)
    }
}


struct EstablishedTunnelLocalConnHandler {
    tunnel: Rc<RefCell<EstablishedTunnel>>,
    interest: Interest,
}

impl EventHandler for EstablishedTunnelLocalConnHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.register(&mut tunnel.local_conn, tunnel.local_token, self.interest)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.reregister(&mut tunnel.local_conn, tunnel.local_token, self.interest)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_writable() && self.interest.is_writable()
            || event.is_readable() && self.interest.is_readable() {
            EstablishedTunnel::process_conn_event(self.tunnel, event_loop, Some(event), None);
        }
    }
}


struct EstablishedTunnelRemoteConnHandler {
    tunnel: Rc<RefCell<EstablishedTunnel>>,
    interest: Interest,
}

impl EventHandler for EstablishedTunnelRemoteConnHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.register(&mut tunnel.remote_conn, tunnel.remote_token, self.interest)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.reregister(&mut tunnel.remote_conn, tunnel.remote_token, self.interest)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_writable() && self.interest.is_writable()
            || event.is_readable() && self.interest.is_readable() {
            EstablishedTunnel::process_conn_event(self.tunnel, event_loop, None, Some(event));
        }
    }
}
