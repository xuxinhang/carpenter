pub mod direct;

// use mio::event::{Source};
use mio::net::TcpStream;
use crate::event_loop::EventLoop;


pub trait ProxyClientReadyCall {
    fn proxy_client_ready(self: Box<Self>, event_loop: &mut EventLoop, peer_source: TcpStream)
        -> std::io::Result<()>;
}
