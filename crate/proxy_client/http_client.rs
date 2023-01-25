use std::io::{self, Write, Read};
use std::net::{SocketAddr};
use mio::{Token, Interest};
use mio::net::{TcpStream};
use mio::event::{Event};
use super::{ProxyClient, ProxyClientReadyCall};
use crate::event_loop::{EventHandler, EventLoop, EventRegistryIntf};
use crate::common::HostAddr;


pub struct ProxyClientHttp {
    server_addr: SocketAddr,
    hostname: Option<String>,
}

impl ProxyClientHttp {
    pub fn new(server_addr: SocketAddr, hostname: Option<String>) -> Self {
        Self { server_addr, hostname }
    }
}

impl ProxyClient for ProxyClientHttp {
    fn connect(
        &self,
        token: Token,
        event_loop: &mut EventLoop,
        tunnel_addr: HostAddr,
        readycall: Box<dyn ProxyClientReadyCall>,
    ) -> io::Result<()> {
        let conn = TcpStream::connect(self.server_addr)?;
        let next_handler = ClientConnectedHandler {
            token,
            conn,
            tunnel_addr,
            _hostname: self.hostname.clone(),
            readycall,
        };
        event_loop.register(Box::new(next_handler))?;
        Ok(())
    }
}

struct ClientConnectedHandler {
    token: Token,
    conn: TcpStream,
    tunnel_addr: HostAddr,
    _hostname: Option<String>,
    readycall: Box<dyn ProxyClientReadyCall>,
}


impl EventHandler for ClientConnectedHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.conn, self.token, Interest::WRITABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.reregister(&mut self.conn, self.token, Interest::WRITABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        let mut conn = self.conn;
        if event.is_writable() {
            match conn.peer_addr() {
                Ok(_addr) => {
                    wd_log::log_debug_ln!("ClientConnectedHandler # peer connected. {}", _addr);
                    let mut http_message = format!("CONNECT {} HTTP/1.1\r\n", self.tunnel_addr.to_string());
                    http_message.push_str(concat!(
                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0\r\n",
                        "Proxy-Connection: keep-alive\r\n",
                        "Connection: keep-alive\r\n",
                    ));
                    http_message.push_str(&format!("Host: {}\r\n", self.tunnel_addr.to_string()));
                    http_message.push_str("\r\n");
                    if let Err(e) = conn.write(http_message.as_bytes()) {
                        wd_log::log_warn_ln!("ClientConnectedHandler # fail to write {:?}", e);
                        return;
                    }

                    event_loop.reregister(Box::new(ClientShakingHandler {
                        token: self.token,
                        conn: conn,
                        readycall: self.readycall,
                    })).unwrap();
                }
                Err(e) if e.kind() == io::ErrorKind::NotConnected => { // TODO
                    wd_log::log_warn_ln!("ClientShakingHandler # Fail to connect due to timeout.");
                }
                Err(e) => {
                    wd_log::log_warn_ln!("ClientShakingHandler # Fail to connect {:?}", e);
                }
            }
        }
    }
}


struct ClientShakingHandler {
    token: Token,
    conn: TcpStream,
    readycall: Box<dyn ProxyClientReadyCall>,
}

impl EventHandler for ClientShakingHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.conn, self.token, Interest::READABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.reregister(&mut self.conn, self.token, Interest::READABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        let mut conn = self.conn;
        if event.is_readable() {
            let mut buf = vec![0u8; 32*1024];
            let _read_size = conn.read(&mut buf);
            if buf.starts_with("HTTP/1.1 200".as_bytes()) {
                if let Err(e) = self.readycall.proxy_client_ready(event_loop, conn) {
                    wd_log::log_warn_ln!("ClientShakingHandler # ready error {:?}", e);
                }
            } else {
                // do nothing
            }
        }
    }
}

