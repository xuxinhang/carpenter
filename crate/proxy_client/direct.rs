use std::io;
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
        &mut self,
        token: Token,
        event_loop: &mut EventLoop,
        readycall: Box<dyn ProxyClientReadyCall>,
    ) -> io::Result<()> {
        let conn = TcpStream::connect(self.socket_addr)?;
        let next_handler = ClientShakingHandler { token, conn, readycall };
        event_loop.register(Box::new(next_handler))?;
        Ok(())
    }
}


struct ClientShakingHandler {
    token: Token,
    conn: TcpStream,
    readycall: Box<dyn ProxyClientReadyCall>,
}


impl EventHandler for ClientShakingHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.conn, self.token, Interest::READABLE | Interest::WRITABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.reregister(&mut self.conn, self.token, Interest::READABLE | Interest::WRITABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if true || event.is_readable() || event.is_writable() { // @HACK: TODO
            if let Ok(Some(e)) | Err(e) = self.conn.take_error() {
                println!("ClientShakingHandler # take_error {:?}", e);
                return;
            }
            match self.conn.peer_addr() {
                Ok(_addr) => {
                    // println!("ClientShakingHandler # peer connected. {}", _addr);
                    if let Err(e) = self.readycall.proxy_client_ready(event_loop, self.conn) {
                        println!("ClientShakingHandler # ready error {:?}", e);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                    // println!("Waiting");
                    event_loop.reregister(self).unwrap();
                }
                Err(e) => {
                    println!("ProxyClientShakingHandler # peer_addr {:?}", e);
                }
            }
        }
    }

}
