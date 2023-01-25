use std::str::FromStr;
use std::io;
use std::io::{Read, Write, Result};
use std::rc::Rc;
use std::cell::RefCell;
use mio::{Interest, Token};
use mio::event::{Event};
use mio::net::{TcpListener, TcpStream};
use std::net::{SocketAddr, IpAddr, Shutdown};
use crate::event_loop::{EventHandler, EventLoop, EventRegistryIntf};
use crate::transformer::{Transformer, TransformerPortState, TransformerResult};
use crate::transformer::directconnect::{DirectConnectionTransformer};
use crate::transformer::sni::{SniRewriterTransformer};
use crate::transformer::httpforward::{HttpForwardTransformer};
use crate::proxy_client::{get_proxy_client, ProxyClientReadyCall};
use crate::dnsresolver::{DnsResolveCallback};
use crate::configuration::{TransformerAction};
use crate::http_header_parser::parse_http_header;
use crate::dnsresolver::DnsQueier;
use crate::common::{Hostname, HostAddr};



pub struct HttpProxyServer {
    listener: TcpListener,
    token: Token,
}

impl HttpProxyServer {
    pub fn new(address: SocketAddr) -> io::Result<Self> {
        let result = TcpListener::bind(address);
        if result.is_err() {
            return Err(result.unwrap_err());
        }
        let listener = result.unwrap();

        Ok(HttpProxyServer {
            listener,
            token: Token(0),
        })
    }

    pub fn initial_register(mut self, event_loop: &mut EventLoop) -> io::Result<()> {
        self.token = event_loop.token.get();
        event_loop.register(Box::new(self))
    }
}

impl EventHandler for HttpProxyServer {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.listener, self.token, Interest::READABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.reregister(&mut self.listener, self.token, Interest::READABLE)
    }

    fn handle(self: Box<Self>, _evt: &Event, event_loop: &mut EventLoop) {
        let x = self.listener.accept();
        if let Err(e) = x {
            wd_log::log_warn_ln!("HttpProxyServer # Fail to accept the incoming connection. ({:?})", e);
            return;
        }

        let (conn, _address) = x.unwrap();
        let h = ClientRequestHandler {
            tunnel: ShakingZeroTunnel{
                token: event_loop.token.get(),
                conn: conn,
            }
        };

        if let Err(e) = event_loop.register(Box::new(h)) {
            wd_log::log_warn_ln!("HttpProxyServer # Fail to register the new client connection {:?}", e);
            return;
        }

        event_loop.reregister(self).unwrap();
    }
}



struct ShakingZeroTunnel {
    token: Token,
    conn: TcpStream,
}

struct ShakingHalfTunnel {
    tunnel_meta: TunnelMeta,
    token: Token,
    conn: TcpStream,
}

struct TunnelMeta {
    _host: HostAddr,
    http_tunnel_mode: bool,
}


struct ClientRequestHandler {
    tunnel: ShakingZeroTunnel,
}

impl EventHandler for ClientRequestHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.tunnel.conn, self.tunnel.token, Interest::READABLE)
    }

    fn handle(mut self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_readable() {
            wd_log::log_debug_ln!("ClientRequestHandler # Coming client request.");
            // TODO: Reuse previous connection.

            let conn = &mut self.tunnel.conn;
            let shutdown_conn = || {
                let r = conn.shutdown(Shutdown::Both);
                if let Err(e) = r {
                    wd_log::log_warn_ln!("Fail to shutdown local conn {}", e);
                }
            };

            let mut msg_buf = vec![0u8; 4*1024*1024];
            let r = conn.peek(&mut msg_buf);
            if let Err(e) = r {
                wd_log::log_error_ln!("ProxyRequestHandler # peek error. {:?}", e);
                shutdown_conn();
                return;
            }

            // Parse http message to pick useful information
            let r = parse_http_header(msg_buf.as_slice());
            if r.is_none() {
                wd_log::log_warn_ln!("Invalid http message.");
                shutdown_conn();
                return;
            }
            let (msg_header_length, msg_header_map, _) = r.unwrap();
            let use_http_tunnel_mode = msg_header_map[":method"].as_str() == "CONNECT";
            let host_str: &str = if use_http_tunnel_mode {
                &msg_header_map[":path"]
            } else {
                let path_str = &msg_header_map[":path"];
                let scheme_prefix = "http://";
                let pos_l = path_str.find(scheme_prefix);
                if pos_l.is_none() {
                    wd_log::log_warn_ln!("Invalid request path, only http supported: {}", path_str);
                    shutdown_conn();
                    return;
                }
                let pos_l = pos_l.unwrap() + scheme_prefix.len();
                let pos_r = &path_str[pos_l..].find("/").unwrap_or(path_str.len() - pos_l) + pos_l;
                &path_str[pos_l..pos_r]
            };

            // Get Hostname from the string
            let r = HostAddr::from_str(host_str);
            if r.is_err() {
                wd_log::log_warn_ln!("ClientRequestHandler # Invalid host {}", host_str);
                shutdown_conn();
                return;
            }
            let remote_host = r.unwrap();

            // Drop this CONNECT message if using http tunnel mode
            if use_http_tunnel_mode {
                let mut trash = vec![0u8; msg_header_length];
                conn.read(&mut trash).unwrap();
            }

            // This tunnel is now Shaking-Half
            let next_tunnel = ShakingHalfTunnel {
                token: self.tunnel.token,
                conn: self.tunnel.conn,
                tunnel_meta: TunnelMeta {
                    _host: remote_host.clone(),
                    http_tunnel_mode: use_http_tunnel_mode,
                }
            };

            // Launch DNS querier
            let query_callback = Box::new(ProxyQueryDoneCallback {
                tunnel: next_tunnel,
                remote_host: remote_host.clone(),
            });
            let querier = DnsQueier::new(remote_host.0.clone());
            querier.query(query_callback, event_loop);
        }
    }
}



struct ProxyQueryDoneCallback {
    tunnel: ShakingHalfTunnel,
    remote_host: HostAddr,
}

impl DnsResolveCallback for ProxyQueryDoneCallback {
    fn ready(self: Box<Self>, addr: Option<IpAddr>, event_loop: &mut EventLoop) {
        if addr.is_none() {
            wd_log::log_warn_ln!("ProxyQueryDoneHandler # Fail to resolve host {:?}", &self.remote_host);
            return;
        }

        let remote_ipaddr = addr.unwrap();
        let remote_port = self.remote_host.1;
        let remote_hostname = self.remote_host.0.clone();
        wd_log::log_info_ln!("DNS Query result for \"{:?}\" is \"{:?}\"",
            remote_hostname, remote_ipaddr);

        let transformer_box = if self.tunnel.tunnel_meta.http_tunnel_mode {
            create_transformer(&self.remote_host).unwrap()
        } else {
            Box::new(HttpForwardTransformer::new(self.remote_host.clone()))
        };

        let client_box = get_proxy_client(&self.remote_host);
        if client_box.is_err() {
            wd_log::log_warn_ln!("ProxyQueryDoneHandler # get_proxy_client error");
            return;
        }
        let (client_box, dns_resolve) = client_box.unwrap();

        let x = client_box.connect(
            event_loop.token.get(),
            event_loop,
            if dns_resolve {
                HostAddr::from(SocketAddr::from((remote_ipaddr, remote_port)))
            } else {
                self.remote_host.clone()
            },
            Box::new(ClientConnectCallback {
                tunnel: self.tunnel,
                transformer: transformer_box,
            }),
        );

        if x.is_err() {
            wd_log::log_warn_ln!("ProxyQueryDoneHandler # ProxyClientDirect::connect error");
            return;
        }
    }
}



struct ClientConnectCallback {
    tunnel: ShakingHalfTunnel,
    transformer: Box<dyn Transformer>,
}

impl ProxyClientReadyCall for ClientConnectCallback {
    fn proxy_client_ready(self: Box<Self>, event_loop: &mut EventLoop, peer_source: TcpStream) -> io::Result<()> {
        let next_tunnel = EstablishedTunnel::new(
            self.tunnel.token, self.tunnel.conn,
            event_loop.token.get(), peer_source,
            self.transformer,
            self.tunnel.tunnel_meta);
        let next_handler = ProxyServerResponseHandler {
            tunnel: next_tunnel,
        };
        event_loop.reregister(Box::new(next_handler)).unwrap();
        Ok(())
    }
}



struct ProxyServerResponseHandler {
    tunnel: EstablishedTunnel,
}

impl EventHandler for ProxyServerResponseHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut self.tunnel;
        registry.register(&mut tunnel.local_conn, tunnel.local_token, Interest::WRITABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut self.tunnel;
        registry.reregister(&mut tunnel.local_conn, tunnel.local_token, Interest::WRITABLE)
    }

    fn handle(mut self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_writable() {
            // response 200 if using http tunnel
            if self.tunnel.tunnel_meta.http_tunnel_mode {
                let message = "HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes();
                let conn = &mut self.tunnel.local_conn;
                if let Err(e) = conn.write(message) {
                    wd_log::log_warn_ln!("ProxyServerResponseHandler # fail to write {:?}", e);
                    return;
                }
            }

            let tunnel_ptr = Rc::new(RefCell::new(self.tunnel));

            event_loop.reregister(Box::new(EstablishedTunnelLocalReadableHandler {
                tunnel: tunnel_ptr.clone(),
            })).unwrap();
            tunnel_ptr.borrow_mut().local_conn_rsta = ConnStatus::Block;

            event_loop.reregister(Box::new(EstablishedTunnelRemoteReadableHandler {
                tunnel: tunnel_ptr.clone(),
            })).unwrap();
            tunnel_ptr.borrow_mut().remote_conn_rsta = ConnStatus::Block;

            event_loop.reregister(Box::new(EstablishedTunnelLocalWritableHandler {
                tunnel: tunnel_ptr.clone(),
            })).unwrap();
            tunnel_ptr.borrow_mut().local_conn_wsta = ConnStatus::Block;

            event_loop.reregister(Box::new(EstablishedTunnelRemoteWritableHandler {
                tunnel: tunnel_ptr.clone(),
            })).unwrap();
            tunnel_ptr.borrow_mut().remote_conn_wsta = ConnStatus::Block;
        }
    }
}



#[derive(PartialEq, Eq)]
enum ConnStatus { Available, Block, Shutdown, Error }

struct EstablishedTunnel {
    tunnel_meta: TunnelMeta,
    //
    local_token: Token,
    local_conn: TcpStream,
    remote_token: Token,
    remote_conn: TcpStream,
    transformer: Box<dyn Transformer>,
    //
    local_rbuf: Vec<u8>,
    local_wbuf: Vec<u8>,
    remote_rbuf: Vec<u8>,
    remote_wbuf: Vec<u8>,
    //
    local_conn_rsta: ConnStatus,
    local_conn_wsta: ConnStatus,
    remote_conn_rsta: ConnStatus,
    remote_conn_wsta: ConnStatus,
}

#[inline(always)]
fn would_block(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::WouldBlock
}

impl EstablishedTunnel {
    fn new(
        local_token: Token,
        local_conn: TcpStream,
        remote_token: Token,
        remote_conn: TcpStream,
        transformer: Box<dyn Transformer>,
        tunnel_meta: TunnelMeta,
    ) -> Self {
        Self {
            tunnel_meta,
            local_token, local_conn, remote_token, remote_conn, transformer,
            local_rbuf: Vec::with_capacity(32 * 1024),
            local_wbuf: Vec::with_capacity(32 * 1024),
            remote_rbuf: Vec::with_capacity(32 * 1024),
            remote_wbuf: Vec::with_capacity(32 * 1024),
            local_conn_rsta: ConnStatus::Available,
            local_conn_wsta: ConnStatus::Available,
            remote_conn_rsta: ConnStatus::Available,
            remote_conn_wsta: ConnStatus::Available,
        }
    }

    fn crash_tunnel(&mut self) {
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

    fn execuate_transfer(&mut self) -> u8 {
        let mut requested_handlers: u8 = 0;
        let mut loop_count: u8 = 0;

        loop {
            let mut is_transfer_active: u8 = 0;
            let mut is_crash_required: u8 = 0;

            // Copy: local_conn.read => transformer.transmit_writable
            let buf = &mut self.local_rbuf;
            let conn = &mut self.local_conn;
            let sta = &mut self.local_conn_rsta;
            let peer_sta = &self.remote_conn_wsta;
            loop {
                if *peer_sta == ConnStatus::Shutdown {
                    let r = conn.shutdown(Shutdown::Read);
                    if let Err(e) = r {
                        wd_log::log_warn_ln!("Fail to shutdown conn {}", e);
                    }
                    *sta = ConnStatus::Shutdown;
                    break;
                }

                match self.transformer.transmit_writable() {
                    TransformerPortState::Closed => {
                        break;
                    }
                    TransformerPortState::Open(0) => {
                        break;
                    }
                    TransformerPortState::Open(_) => {}
                }

                if buf.len() == 0 {
                    if *sta == ConnStatus::Available {
                        buf.resize(buf.capacity(), 0);
                        match conn.read(buf.as_mut_slice()) {
                            Ok(0) => {
                                *sta = ConnStatus::Shutdown;
                                buf.resize(0, 0);
                                wd_log::log_debug_ln!("localconn read {:?} (shutdown)", 0);
                            }
                            Ok(s) => {
                                *sta = ConnStatus::Available;
                                buf.resize(s, 0);
                                wd_log::log_debug_ln!("localconn read {:?} {:?}", s, buf[0]);
                            }
                            Err(ref e) if would_block(e) => { // register handler
                                *sta = ConnStatus::Block;
                                requested_handlers |= CONN_EVT_LOCAL_R;
                                buf.resize(0, 0);
                                wd_log::log_debug_ln!("localconn read Block");
                                break;
                            }
                            Err(_e) => { // shutdown tunnel in force
                                *sta = ConnStatus::Error;
                                is_crash_required += 1;
                                buf.resize(0, 0);
                                wd_log::log_debug_ln!("localconn read Err {:?}", _e);
                                break;
                            }
                        }
                    }
                }
                if buf.len() == 0 {
                    break;
                }

                match self.transformer.transmit_write(buf) {
                    TransformerResult::Ok(s) => {
                        wd_log::log_debug_ln!("transformer transmit_write Ok {} {:?}", s, buf[0]);
                        buf.drain(0..s);
                    }
                    e => {
                        is_crash_required += 1;
                        wd_log::log_debug_ln!("transformer transmit_write Error: {:?}", e);
                        break;
                    }
                }

                is_transfer_active |= 1;
            }

            // Copy: remote_conn.read => transformer.receive_writable
            let buf = &mut self.remote_rbuf;
            let conn = &mut self.remote_conn;
            let sta = &mut self.remote_conn_rsta;
            let peer_sta = &self.local_conn_wsta;
            loop {
                if *peer_sta == ConnStatus::Shutdown {
                    let r = conn.shutdown(Shutdown::Read);
                    if let Err(e) = r {
                        wd_log::log_warn_ln!("Fail to shutdown conn {}", e);
                    }
                    *sta = ConnStatus::Shutdown;
                    break;
                }

                match self.transformer.receive_writable() {
                    TransformerPortState::Closed => {
                        break;
                    }
                    TransformerPortState::Open(0) => {
                        break;
                    }
                    TransformerPortState::Open(_) => {}
                }

                if buf.len() == 0 {
                    if *sta == ConnStatus::Available {
                        buf.resize(buf.capacity(), 0);
                        match conn.read(buf) {
                            Ok(0) => {
                                *sta = ConnStatus::Shutdown;
                                buf.resize(0, 0);
                                wd_log::log_debug_ln!("remoteconn read Ok {:?} (shutdown)", 0);
                            }
                            Ok(s) => {
                                *sta = ConnStatus::Available;
                                buf.resize(s, 0);
                                wd_log::log_debug_ln!("remoteconn read Ok {:?}", s);
                            }
                            Err(ref e) if would_block(e) => { // register handler
                                *sta = ConnStatus::Block;
                                requested_handlers |= CONN_EVT_REMOTE_R;
                                buf.resize(0, 0);
                                wd_log::log_debug_ln!("remoteconn read Block");
                                break;
                            }
                            Err(_e) => { // shutdown tunnel in force
                                is_crash_required += 1;
                                buf.resize(0, 0);
                                wd_log::log_debug_ln!("remoteconn read Err {:?}", _e);
                                break;
                            }
                        }
                    }
                }
                if buf.len() == 0 {
                    break;
                }

                match self.transformer.receive_write(buf) {
                    TransformerResult::Ok(s) => {
                        buf.drain(0..s);
                        wd_log::log_debug_ln!("transformer receive_write Ok {}", s);
                    }
                    e => {
                        is_crash_required += 1;
                        wd_log::log_debug_ln!("transformer transmit_write Error: {:?}", e);
                        break;
                    }
                }

                is_transfer_active |= 1;
            }

            // Copy: transformer.transmit_readable => remote_conn.write
            let buf = &mut self.remote_wbuf;
            let conn = &mut self.remote_conn;
            let sta = &mut self.remote_conn_wsta;
            let peer_sta = &self.local_conn_rsta;
            loop {
                if *sta != ConnStatus::Available {
                    break;
                }

                if buf.len() == 0 {
                    if let TransformerPortState::Open(_) = self.transformer.transmit_readable() {
                        buf.resize(buf.capacity(), 0);
                        if let TransformerResult::Ok(s) = self.transformer.transmit_read(buf) {
                            buf.resize(s, 0);
                        } else {
                            is_crash_required += 1;
                            break;
                        }
                    }
                }
                if buf.len() == 0 {
                    if *peer_sta == ConnStatus::Shutdown {
                        let r = conn.shutdown(Shutdown::Write);
                        if let Err(e) = r {
                            wd_log::log_warn_ln!("Fail to shutdown conn {}", e);
                        }
                        *sta = ConnStatus::Shutdown;
                    }
                    break;
                }

                match conn.write(buf) {
                    Ok(s) => {
                        wd_log::log_debug_ln!("remoteconn write Ok {} {:?}", s, buf[0]);
                        buf.drain(0..s);
                    }
                    Err(ref e) if would_block(e) => {
                        *sta = ConnStatus::Block;
                        requested_handlers |= CONN_EVT_REMOTE_W;
                        wd_log::log_debug_ln!("remoteconn write Block");
                        break;
                    }
                    Err(_e) => {
                        is_crash_required += 1;
                        wd_log::log_debug_ln!("remoteconn write Err {:?}", _e);
                        break;
                    }
                }

                is_transfer_active |= 1;
            }

            // Copy: transformer.receive_readable => local_conn.write
            let buf = &mut self.local_wbuf;
            let conn = &mut self.local_conn;
            let sta = &mut self.local_conn_wsta;
            let peer_sta = &self.remote_conn_rsta;
            loop {
                if *sta != ConnStatus::Available {
                    break;
                }

                if buf.len() == 0 {
                    if let TransformerPortState::Open(_) = self.transformer.receive_readable() {
                        buf.resize(buf.capacity(), 0);
                        if let TransformerResult::Ok(s) = self.transformer.receive_read(buf) {
                            buf.resize(s, 0);
                        } else {
                            is_crash_required += 1;
                            break;
                        }
                    }
                }
                if buf.len() == 0 {
                    if *peer_sta == ConnStatus::Shutdown {
                        let r = conn.shutdown(Shutdown::Write);
                        if let Err(e) = r {
                            wd_log::log_warn_ln!("Fail to shutdown conn {}", e);
                        }
                        *sta = ConnStatus::Shutdown;
                    }
                    break;
                }

                match conn.write(buf) {
                    Ok(s) => {
                        wd_log::log_debug_ln!("localconn write {}", s);
                        buf.drain(0..s);
                    }
                    Err(ref e) if would_block(e) => {
                        *sta = ConnStatus::Block;
                        requested_handlers |= CONN_EVT_REMOTE_W;
                        wd_log::log_debug_ln!("localconn write Block");
                        break;
                    }
                    Err(_e) => {
                        is_crash_required += 1;
                        wd_log::log_debug_ln!("localconn write Error");
                        break;
                    }
                }

                is_transfer_active |= 1;
            }

            // crash if required
            if is_crash_required != 0 {
                wd_log::log_debug_ln!("crashing tunnel");
                self.crash_tunnel();
                return 0;
            }

            // exit loop: if no data transfered this round or too many rounds has execuated.
            loop_count += 1;
            if is_transfer_active == 0 || loop_count > 64 {
                break;
            }
        }

        return requested_handlers;
    }

    fn process_conn_status_available(tunnel_ptr: Rc<RefCell<Self>>, event_loop: &mut EventLoop, mask: u8) {
        let mut tunnel = tunnel_ptr.borrow_mut();

        if (mask & CONN_EVT_LOCAL_R) != 0 { tunnel.local_conn_rsta = ConnStatus::Available; }
        if (mask & CONN_EVT_LOCAL_W) != 0 { tunnel.local_conn_wsta = ConnStatus::Available; }
        if (mask & CONN_EVT_REMOTE_R) != 0 { tunnel.remote_conn_rsta = ConnStatus::Available; }
        if (mask & CONN_EVT_REMOTE_W) != 0 { tunnel.remote_conn_wsta = ConnStatus::Available; }

        let hreq = tunnel.execuate_transfer();

        drop(tunnel);

        if (hreq & CONN_EVT_LOCAL_R) != 0 {
            event_loop.reregister(Box::new(EstablishedTunnelLocalReadableHandler {
                tunnel: tunnel_ptr.clone(),
            })).unwrap();
        }
        if (hreq & CONN_EVT_LOCAL_W) != 0 {
            event_loop.reregister(Box::new(EstablishedTunnelLocalWritableHandler {
                tunnel: tunnel_ptr.clone(),
            })).unwrap();
        }
        if (hreq & CONN_EVT_REMOTE_R) != 0 {
            event_loop.reregister(Box::new(EstablishedTunnelRemoteReadableHandler {
                tunnel: tunnel_ptr.clone(),
            })).unwrap();
        }
        if (hreq & CONN_EVT_REMOTE_W) != 0 {
            event_loop.reregister(Box::new(EstablishedTunnelRemoteWritableHandler {
                tunnel: tunnel_ptr.clone(),
            })).unwrap();
        }
    }
}

const CONN_EVT_LOCAL_R: u8 = 0b0001;
const CONN_EVT_LOCAL_W: u8 = 0b0010;
const CONN_EVT_REMOTE_R: u8 = 0b0100;
const CONN_EVT_REMOTE_W: u8 = 0b1000;


struct EstablishedTunnelLocalReadableHandler {
    tunnel: Rc<RefCell<EstablishedTunnel>>,
}

impl EventHandler for EstablishedTunnelLocalReadableHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.register(&mut tunnel.local_conn, tunnel.local_token, Interest::READABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.reregister(&mut tunnel.local_conn, tunnel.local_token, Interest::READABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_readable() {
            EstablishedTunnel::process_conn_status_available(
                self.tunnel, event_loop, CONN_EVT_LOCAL_R);
        }
    }
}


struct EstablishedTunnelRemoteReadableHandler {
    tunnel: Rc<RefCell<EstablishedTunnel>>,
}

impl EventHandler for EstablishedTunnelRemoteReadableHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.register(&mut tunnel.remote_conn, tunnel.remote_token, Interest::READABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.reregister(&mut tunnel.remote_conn, tunnel.remote_token, Interest::READABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_readable() {
            EstablishedTunnel::process_conn_status_available(
                self.tunnel, event_loop, CONN_EVT_REMOTE_R);
        }
    }
}


struct EstablishedTunnelRemoteWritableHandler {
    tunnel: Rc<RefCell<EstablishedTunnel>>,
}

impl EventHandler for EstablishedTunnelRemoteWritableHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.register(&mut tunnel.remote_conn, tunnel.remote_token, Interest::WRITABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.reregister(&mut tunnel.remote_conn, tunnel.remote_token, Interest::WRITABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_writable() {
            EstablishedTunnel::process_conn_status_available(
                self.tunnel, event_loop, CONN_EVT_REMOTE_W);
        }
    }
}


struct EstablishedTunnelLocalWritableHandler {
    tunnel: Rc<RefCell<EstablishedTunnel>>,
}

impl EventHandler for EstablishedTunnelLocalWritableHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.register(&mut tunnel.local_conn, tunnel.local_token, Interest::WRITABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.reregister(&mut tunnel.local_conn, tunnel.local_token, Interest::WRITABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_writable() {
            EstablishedTunnel::process_conn_status_available(
                self.tunnel, event_loop, CONN_EVT_LOCAL_W);
        }
    }
}


fn create_transformer(host: &HostAddr) -> Result<Box<dyn Transformer>> {
    let global_config = crate::global::get_global_config();
    let transformer_config = global_config.get_transformer_action_by_host(host);

    let transformer_box: Box<dyn Transformer> = match transformer_config {
        Some(TransformerAction::SniTransformer(s)) => {
            let sni_name = match s.as_str() {
                "_" => None,
                "*" => Some(host.0.clone()),
                h => {
                    if let Ok(x) = Hostname::from_str(h) {
                        Some(x)
                    } else {
                        wd_log::log_warn_ln!("Invalid hostname {}", h);
                        Some(host.0.clone())
                    }
                }
            };
            wd_log::log_info_ln!("Use transformer: SNI Rewritter \"{}\"",
                if let Some(ref v) = sni_name { v.to_string() } else { "<omitted>".to_string() });
            let transformer = SniRewriterTransformer::new("", sni_name, host.0.clone());
            if let Err(e) = transformer {
                wd_log::log_info_ln!("ProxyQueryDoneCallback # SniRewriterTransformer::new {:?}", e);
                return Err(e);
            }
            Box::new(transformer.unwrap())
        }
        Some(TransformerAction::DirectTransformer) | None => {
            wd_log::log_info_ln!("Use transformer: Direct");
            Box::new(DirectConnectionTransformer::new())
        }
    };

    return Ok(transformer_box);
}
