pub mod direct;
pub mod http_client;

use std::io;
use mio::Token;
use mio::net::TcpStream;
use crate::event_loop::EventLoop;
use crate::common::HostAddr;
use crate::configuration::{OutboundAction, OutboundClientProtocol};


pub trait ProxyClient {
    fn connect(
        &self,
        token: Token,
        event_loop: &mut EventLoop,
        tunnel_addr: HostAddr,
        readycall: Box<dyn ProxyClientReadyCall>,
    ) -> io::Result<()>;
}

pub trait ProxyClientReadyCall {
    fn proxy_client_ready(
        self: Box<Self>,
        event_loop: &mut EventLoop,
        peer_source: TcpStream,
        peer_token: Token,
    ) -> std::io::Result<()>;
}


pub fn get_proxy_client(host: &HostAddr) -> Result<(Box<dyn ProxyClient>, bool), String> {
    let global_config = crate::global::get_global_config();
    let outbound_config = global_config.get_outbound_action_by_host(&HostAddr(host.0.clone(), 0)); // TODO

    let (proxy_client_box, dns_resolve): (Box<dyn ProxyClient>, bool) = match outbound_config {
        Some(OutboundAction::Server(server_name)) => {
            let server_config = crate::global::get_global_config().core.outbound_client.get(&server_name);
            if server_config.is_none() {
                return Err("Unknown server name".to_string());
            }
            let server_config = server_config.unwrap();

            match server_config.protocol {
                OutboundClientProtocol::Http => {
                    wd_log::log_debug_ln!("get_proxy_client :: use ProxyClientHttp");
                    (Box::new(http_client::ProxyClientHttp::new(server_config.addr.clone(), None)),
                        server_config.dns_resolve)
                }
            }
        }
        Some(OutboundAction::Direct) | None => {
            wd_log::log_debug_ln!("get_proxy_client :: use ProxyClientDirect");
            (Box::new(direct::ProxyClientDirect::new()), true)
        }
    };

    Ok((proxy_client_box, dns_resolve))
}
