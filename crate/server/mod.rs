use crate::event_loop::{EventLoop};


pub mod prepare;
pub mod http_server;
pub mod https_server;

pub trait ProxyServer {
    fn launch(self, event_loop: &mut EventLoop) -> std::io::Result<()>;
}
