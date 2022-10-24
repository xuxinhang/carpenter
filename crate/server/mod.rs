use crate::event_loop::{EventLoop};


pub mod http_server;

pub trait ProxyServer {
    fn initial_register(self, event_loop: &mut EventLoop) -> std::io::Result<()>;
}
