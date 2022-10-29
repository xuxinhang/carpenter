use std::io;
use std::time::{SystemTime, Duration};
use std::net::{SocketAddr};
use mio::{Token, Interest};
use mio::net::{TcpStream};
use mio::event::{Event};
use crate::event_loop::{EventHandler, EventLoop, EventRegistryIntf};
use crate::proxy_client::ProxyClientReadyCall;


pub struct ProxyClientDirect {
    socket_addr: SocketAddr,
}

impl ProxyClientDirect {
    pub fn new(socket_addr: SocketAddr) -> Self {
        Self { socket_addr }
    }

    pub fn connect(
        &self,
        token: Token,
        event_loop: &mut EventLoop,
        readycall: Box<dyn ProxyClientReadyCall>,
    ) -> io::Result<()> {
        let conn = TcpStream::connect(self.socket_addr)?;
        let next_handler = ClientShakingHandler {
            token, conn, readycall,
            timeout_systemtime: SystemTime::now().checked_add(Duration::from_secs(60)).unwrap(),
        };
        event_loop.register(Box::new(next_handler))?;
        Ok(())
    }
}


struct ClientShakingHandler {
    token: Token,
    conn: TcpStream,
    readycall: Box<dyn ProxyClientReadyCall>,
    timeout_systemtime: SystemTime,
}


impl EventHandler for ClientShakingHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.conn, self.token, Interest::WRITABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.reregister(&mut self.conn, self.token, Interest::WRITABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_writable() { // @HACK: TODO
            match self.conn.peer_addr() {
                Ok(_addr) => {
                    wd_log::log_debug_ln!("ClientShakingHandler # peer connected. {}", _addr);
                    if let Err(e) = self.readycall.proxy_client_ready(event_loop, self.conn) {
                        wd_log::log_warn_ln!("ClientShakingHandler # ready error {:?}", e);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotConnected => { // TODO
                    if self.timeout_systemtime.elapsed().is_err() {
                        event_loop.reregister(self).unwrap();
                    } else {
                        wd_log::log_warn_ln!("ClientShakingHandler # Fail to connect due to timeout.");
                    }
                }
                Err(e) => {
                    wd_log::log_warn_ln!("ClientShakingHandler # Fail to connect {:?}", e);
                }
            }
        }
    }

}
