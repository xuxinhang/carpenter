use std::rc::Rc;
use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, Shutdown};
use mio::{Interest, Token};
use mio::event::{Event};
use mio::net::{TcpListener, TcpStream};
use rustls::{ServerConfig, ServerConnection};
use crate::event_loop::{EventHandler, EventLoop, EventRegistryIntf};
use crate::certmgr::certstorage::{get_cert_data_by_hostname};
use crate::transformer::{create_transformer_unit, TransformerUnit, TransformerUnitError, TransformerUnitResult};
use super::ProxyServer;
use super::prepare::prepare_proxy_client_to_remote_host;
use crate::proxy_client::{ProxyClientReadyCall};
use crate::common::HostName;
use super::tunnel::{TunnelMeta, EstablishedTunnel};
use super::http_proxy_utils::parse_http_proxy_message;


pub struct ProxyServerHttpOverTls {
    listener_socket: TcpListener,
    listener_token: Token,
    server_hostname: HostName,
}

impl ProxyServerHttpOverTls {
    pub fn new(addr: SocketAddr, hostname: HostName) -> std::io::Result<Self> {
        let listener_socket = TcpListener::bind(addr)?;
        Ok(Self {
            listener_socket,
            listener_token: Token(0),
            server_hostname: hostname,
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
            ShakingConnection::new(conn, conn_token, self.server_hostname.clone()));
        event_loop.register(tunnel).unwrap();

        // do not forget to receive the further connection
        event_loop.reregister(self).unwrap();
    }
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
    fn new(conn: TcpStream, conn_token: Token, host: HostName) -> Self {
        let (local_tls_cert_data, local_tls_pkey_data) =
            get_cert_data_by_hostname(Some(host)).unwrap();
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
                http_forward_mode: !use_http_tunnel_mode,
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
                http_message: self.received_text,
                client_transformer: None,
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
    http_message: Vec<u8>,
    client_transformer: Option<Box<dyn TransformerUnit>>,
}

impl ProxyClientReadyCall for ProxyServerResponseHandler {
    fn proxy_client_ready(
        mut self: Box<Self>,
        event_loop: &mut EventLoop,
        peer_source: TcpStream,
        peer_token: Token,
        client_transformer: Option<Box<dyn TransformerUnit>>,
    ) -> std::io::Result<()> {
        self.peer_conn = Some(peer_source);
        self.peer_token = Some(peer_token);
        self.client_transformer = client_transformer;
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
            if !self.meta.http_forward_mode {
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
            if let Some(t) = self.client_transformer {
                tunnel_transformers.push(t);
            }

            let early_message_ref = if self.meta.http_forward_mode {
                Some(self.http_message.as_slice())
            } else {
                None
            };

            let tunnel_cell = Rc::new(RefCell::new(EstablishedTunnel::new(
                tunnel_transformers,
                self.meta,
                self.conn,
                self.conn_token,
                self.peer_conn.unwrap(),
                self.peer_token.unwrap(),
                early_message_ref,
            )));

            EstablishedTunnel::process_conn_event(tunnel_cell, event_loop, None, None);
        }
    }
}


#[inline(always)]
fn would_block(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::WouldBlock
}

#[derive(PartialEq, Eq, Debug)]
enum ConnStatus { Available, Block, /* Shutdown, Error */ }


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

