use std::io::{self, Write, Read};
use std::net::{SocketAddr, Shutdown};
use std::sync::Arc;
use mio::{Token, Interest};
use mio::net::{TcpStream};
use mio::event::{Event};
use rustls::ClientConnection;
use super::{ProxyClient, ProxyClientReadyCall};
use crate::event_loop::{EventHandler, EventLoop, EventRegistryIntf};
use crate::transformer::{TransformerUnit, TransformerUnitResult, TransformerUnitError};
use crate::common::HostAddr;
use crate::transformer::certstorage::get_other_trust_anchor_data;


fn check_response(buf: &[u8]) -> bool {
    if buf.starts_with("HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes()) {
        true
    } else {
        false
    }
}


pub struct ProxyClientHttpOverTls {
    server_addr: SocketAddr,
    _hostname: Option<String>,
}

impl ProxyClientHttpOverTls {
    pub fn new(server_addr: SocketAddr, hostname: Option<String>) -> Self {
        Self {
            server_addr,
            _hostname: hostname,
        }
    }
}

impl ProxyClient for ProxyClientHttpOverTls {
    fn connect(
        &self,
        token: Token,
        event_loop: &mut EventLoop,
        tunnel_addr: HostAddr,
        readycall: Box<dyn ProxyClientReadyCall>,
    ) -> io::Result<()> {
        let conn = TcpStream::connect(self.server_addr)?;

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS
                .0
                .iter()
                .map(|ta| {
                    rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                })
        );
        if let Some(anchor) = get_other_trust_anchor_data("root.crt.crt").unwrap() {
            let ota = vec![anchor];
            root_store.add_server_trust_anchors(ota.iter().map(|ta| ta.clone()));
        }

        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let tls = ClientConnection::new(
            Arc::new(config),
            "localhost".try_into().unwrap(),
        ).unwrap();

        let mut text = String::new();
        text.push_str(&format!("CONNECT {} HTTP/1.1\r\n", tunnel_addr.to_string()));
        text.push_str(concat!(
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0\r\n",
            "Proxy-Connection: keep-alive\r\n",
            "Connection: keep-alive\r\n",
        ));
        text.push_str(&format!("Host: {}\r\n", tunnel_addr.to_string()));
        text.push_str("\r\n");
        let mut tls_writter_buf = Vec::new();
        tls_writter_buf.extend_from_slice(text.as_bytes());

        let next_handler = ClientConnectedHandler {
            conn_token: token,
            conn,
            conn_rsta: ConnStatus::Block,
            conn_wsta: ConnStatus::Block,
            tls,
            wbuf: tls_writter_buf,
            rbuf: Vec::with_capacity(32*1024),
            _tunnel_addr: tunnel_addr,
            readycall,
        };
        event_loop.register(Box::new(next_handler))?;
        Ok(())
    }
}

struct ClientConnectedHandler {
    conn_token: Token,
    conn: TcpStream,
    conn_rsta: ConnStatus,
    conn_wsta: ConnStatus,
    tls: ClientConnection,
    wbuf: Vec<u8>,
    rbuf: Vec<u8>,
    _tunnel_addr: HostAddr,
    readycall: Box<dyn ProxyClientReadyCall>,
}


#[inline(always)]
fn would_block(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::WouldBlock
}

#[derive(PartialEq, Eq, Debug)]
enum ConnStatus { Available, Block /*, Shutdown, Error*/ }


impl EventHandler for ClientConnectedHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.conn, self.conn_token, Interest::WRITABLE)
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
        let conn = &mut self.conn;
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

        loop {
            let mut transfer_size = 0;
            let tls = &mut self.tls;

            while !self.wbuf.is_empty() {
                match tls.writer().write(self.wbuf.as_slice()) {
                    Err(ref e) if would_block(e) => {
                        break;
                    }
                    Err(ref e) => {
                        wd_log::log_error_ln!("ClientConnectedHandler # Error {:?}", e);
                        shutdown_conn(conn);
                        return;
                    }
                    Ok(s) => {
                        self.wbuf.drain(0..s);
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
                        wd_log::log_error_ln!("ClientConnectedHandler # Error {:?}", e);
                        shutdown_conn(conn);
                        return;
                    }
                    Ok(s) => {
                        transfer_size += s;
                    }
                }
            }

            loop {
                let mut buf: [u8; 32*1024] = [0; 32*1024];
                match tls.reader().read(&mut buf) {
                    Err(ref e) if would_block(e) => {
                        break;
                    }
                    Err(ref e) => {
                        wd_log::log_error_ln!("ClientConnectedHandler # reader {:?}", e);
                        shutdown_conn(conn);
                        return;
                    }
                    Ok(0) => {
                        wd_log::log_warn_ln!("ClientConnectedHandler # tls closed");
                        shutdown_conn(conn);
                        return;
                    }
                    Ok(s) => {
                        self.rbuf.write(&buf[..s]).unwrap();
                        transfer_size += s;
                    }
                }
            }

            while tls.wants_read() && self.conn_rsta == ConnStatus::Available {
                match tls.read_tls(conn) {
                    Err(ref e) if would_block(e) => {
                        self.conn_rsta = ConnStatus::Block;
                        break;
                    }
                    Err(ref e) => {
                        wd_log::log_error_ln!("ClientConnectedHandler # Io Error {:?}", e);
                        shutdown_conn(conn);
                        return;
                    }
                    Ok(0) => {
                        wd_log::log_warn_ln!("ClientConnectedHandler # connection closed");
                        shutdown_conn(conn);
                        return;
                    }
                    Ok(s) => {
                        transfer_size += s;
                        if let Err(e) = tls.process_new_packets() {
                            wd_log::log_error_ln!("ClientConnectedHandler # Tls Error {:?}", e);
                            shutdown_conn(conn);
                            return;
                        }
                    }
                }
            }

            if transfer_size == 0 { break; }
        }

        if !check_response(self.rbuf.as_slice()) {
            event_loop.reregister(self).unwrap();
            return;
        }

        let tf = HttpOverTlsClientFerryTransformer {
            tls: self.tls,
            has_closed: false,
        };

        if let Err(e) = self.readycall.proxy_client_ready(
            event_loop, self.conn, self.conn_token, Some(Box::new(tf)),
        ) {
            wd_log::log_warn_ln!("ClientConnectedHandler # ready error {:?}", e);
            return;
        }
    }
}


struct HttpOverTlsClientFerryTransformer {
    tls: ClientConnection,
    has_closed: bool,
}

impl TransformerUnit for HttpOverTlsClientFerryTransformer {
    fn receive_write(&mut self, mut buf: &[u8]) -> TransformerUnitResult {
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

    fn receive_read(&mut self, buf: &mut [u8]) -> TransformerUnitResult {
        let s = self.tls.reader().read(buf).map_err(|e| TransformerUnitError::IoError(e))?;
        if s == 0 && self.has_closed {
            Err(TransformerUnitError::ClosedError())
        } else {
            Ok(s)
        }
    }

    fn receive_end(&mut self) -> TransformerUnitResult {
        self.tls.send_close_notify();
        self.has_closed = true;
        Ok(0)
    }

    fn transmit_write(&mut self, buf: &[u8]) -> TransformerUnitResult {
        let s = self.tls.writer().write(buf).map_err(|e| TransformerUnitError::IoError(e))?;
        if s == 0 && self.has_closed {
            Err(TransformerUnitError::ClosedError())
        } else {
            Ok(s)
        }
    }

    fn transmit_read(&mut self, mut buf: &mut [u8]) -> TransformerUnitResult {
        let s = self.tls.write_tls(&mut buf).map_err(|e| TransformerUnitError::IoError(e))?;
        if s == 0 && self.has_closed {
            Err(TransformerUnitError::ClosedError())
        } else {
            Ok(s)
        }
    }

    fn transmit_end(&mut self) ->TransformerUnitResult {
        self.tls.send_close_notify();
        self.has_closed = true;
        Ok(0)
    }
}
