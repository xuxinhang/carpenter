use std::io;
use std::net::SocketAddr;
use mio::event::Event;
use mio::net::TcpListener;
use mio::{Interest, Token};
use crate::bridge::{BridgeChain, BridgeStation, BridgeTCPStreamLocalTerminal};
use crate::configuration::InboundServerProtocol;
use crate::event_loop::{EventHandler, EventLoop, EventRegistryIntf};
use crate::stations::server::http_tunnel::HTTPTunnelProtocolStation;

pub fn launch_server_listener(
    protocol: InboundServerProtocol,
    address: SocketAddr,
    event_loop: &mut EventLoop,
) -> io::Result<()> {
    let res = TcpListener::bind(address);
    if res.is_err() {
        return Err(res.unwrap_err());
    }

    let listener = res?;
    let listener_addr = listener.local_addr();
    let listener_token = event_loop.token.get();
    let server = LocalStreamIncomingGenericServer {
        listener, listener_token, protocol,
        listener_registered: 0,
    };

    event_loop.collect(Box::new(server))?;
    wd_log::log_warn_ln!("LocalStreamIncomingGenericServer # Listening {:?}", listener_addr);
    Ok(())
}

struct LocalStreamIncomingGenericServer {
    listener: TcpListener,
    listener_token: Token,
    listener_registered: usize,
    protocol: InboundServerProtocol,
}

impl EventHandler for LocalStreamIncomingGenericServer {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.listener, self.listener_token, Interest::READABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.reregister(&mut self.listener, self.listener_token, Interest::READABLE)
    }

    fn collect(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        if self.listener_registered == 0 {
            self.register(registry)?;
        } else {
            self.reregister(registry)?;
        }
        self.listener_registered += 1;
        Ok(())
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        let s = self.listener.accept();
        if let Err(e) = s {
            wd_log::log_warn_ln!("LocalStreamIncomingGenericServer # Fail to accept the incoming connection. ({:?})", e);
            return;
        }
        let (local_stream, _) = s.unwrap();
        local_stream.set_nodelay(true).unwrap();
        let stations = get_initial_stations_by_protocol(self.protocol.clone());
        let local_terminal =
            BridgeTCPStreamLocalTerminal::from_stream(local_stream, event_loop.token.get());
        let bridge = BridgeChain::from_existed(local_terminal, stations);
        event_loop.collect(Box::new(bridge)).unwrap();

        event_loop.reregister(self).unwrap();
    }
}


fn get_initial_stations_by_protocol(proto: InboundServerProtocol) -> Vec<Box<dyn BridgeStation>>{
    match proto {
        InboundServerProtocol::Http => {
            let proxy_server = HTTPTunnelProtocolStation::new();
            vec![Box::new(proxy_server)]
        }
        _ => todo!(),
    }
}