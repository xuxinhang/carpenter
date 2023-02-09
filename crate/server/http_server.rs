use std::io;
use std::io::{Read, Write};
use std::rc::Rc;
use std::cell::RefCell;
use mio::{Interest, Token};
use mio::event::{Event};
use mio::net::{TcpListener, TcpStream};
use std::net::{SocketAddr, Shutdown};
use crate::event_loop::{EventHandler, EventLoop, EventRegistryIntf};
use crate::transformer::{create_transformer_unit, TransformerUnit};
use crate::proxy_client::ProxyClientReadyCall;
use super::tunnel::{TunnelMeta, EstablishedTunnel};
use super::ProxyServer;


pub struct HttpProxyServer {
    listener: TcpListener,
    token: Token,
}

impl HttpProxyServer {
    pub fn new(address: SocketAddr) -> io::Result<Self> {
        let result = TcpListener::bind(address);
        if result.is_err() {
            return Err(result.unwrap_err());
        }
        let listener = result.unwrap();

        Ok(HttpProxyServer {
            listener,
            token: Token(0),
        })
    }
}

impl ProxyServer for HttpProxyServer {
    fn launch(mut self, event_loop: &mut EventLoop) -> io::Result<()> {
        self.token = event_loop.token.get();
        event_loop.register(Box::new(self))
    }
}

impl EventHandler for HttpProxyServer {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.listener, self.token, Interest::READABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.reregister(&mut self.listener, self.token, Interest::READABLE)
    }

    fn handle(self: Box<Self>, _evt: &Event, event_loop: &mut EventLoop) {
        let x = self.listener.accept();
        if let Err(e) = x {
            wd_log::log_warn_ln!("HttpProxyServer # Fail to accept the incoming connection. ({:?})", e);
            return;
        }

        let (conn, _address) = x.unwrap();
        let h = ClientRequestHandler {
            tunnel: ShakingZeroTunnel{
                token: event_loop.token.get(),
                conn: conn,
            }
        };

        if let Err(e) = event_loop.register(Box::new(h)) {
            wd_log::log_warn_ln!("HttpProxyServer # Fail to register the new client connection {:?}", e);
            return;
        }

        event_loop.reregister(self).unwrap();
    }
}



struct ShakingZeroTunnel {
    token: Token,
    conn: TcpStream,
}

struct ShakingHalfTunnel {
    tunnel_meta: TunnelMeta,
    token: Token,
    conn: TcpStream,
}


struct ClientRequestHandler {
    tunnel: ShakingZeroTunnel,
}

impl EventHandler for ClientRequestHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.tunnel.conn, self.tunnel.token, Interest::READABLE)
    }

    fn handle(mut self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_readable() {
            wd_log::log_debug_ln!("ClientRequestHandler # Coming client request.");

            let conn = &mut self.tunnel.conn;
            let shutdown_conn = || {
                let r = conn.shutdown(Shutdown::Both);
                if let Err(e) = r {
                    wd_log::log_warn_ln!("Fail to shutdown local conn {}", e);
                }
            };

            let mut msg_buf = vec![0u8; 32*1024];
            let r = conn.peek(&mut msg_buf);
            if let Err(e) = r {
                wd_log::log_error_ln!("ProxyRequestHandler # peek error. {:?}", e);
                shutdown_conn();
                return;
            }

            let r = super::http_proxy_utils::parse_http_proxy_message(&msg_buf);
            if let Err(e) = r {
                wd_log::log_warn_ln!("ClientRequestHandler # {}", e);
                shutdown_conn();
                return;
            }
            let (msg_header_length, host, use_http_tunnel_mode) = r.unwrap();

            // Drop this CONNECT message if using http tunnel mode
            if use_http_tunnel_mode {
                let mut trash = vec![0u8; msg_header_length];
                conn.read(&mut trash).unwrap();
            }

            // This tunnel is now Shaking-Half
            let tunnel_meta = TunnelMeta {
                _remote_host: host.clone(),
                http_forward_mode: !use_http_tunnel_mode,
            };
            let next_tunnel = ShakingHalfTunnel {
                token: self.tunnel.token,
                conn: self.tunnel.conn,
                tunnel_meta,
            };

            let transformer = create_transformer_unit(&host, use_http_tunnel_mode).unwrap();
            let proxy_client_callback = ClientConnectCallback {
                tunnel: next_tunnel,
                transformer,
            };

            super::prepare::prepare_proxy_client_to_remote_host(
                host.clone(),
                event_loop,
                Box::new(proxy_client_callback),
            );
            return;
        }
    }
}


struct ClientConnectCallback {
    tunnel: ShakingHalfTunnel,
    transformer: Box<dyn TransformerUnit>,
}

impl ProxyClientReadyCall for ClientConnectCallback {
    fn proxy_client_ready(
        self: Box<Self>,
        event_loop: &mut EventLoop,
        peer_source: TcpStream,
        peer_token: Token,
        client_transformer: Option<Box<dyn TransformerUnit>>, // TODO
    ) -> io::Result<()> {
        let next_handler = ProxyServerResponseHandler {
            local_token: self.tunnel.token,
            local_conn: self.tunnel.conn,
            remote_token: peer_token,
            remote_conn: peer_source,
            transformer: self.transformer,
            client_transformer,
            tunnel_meta: self.tunnel.tunnel_meta,
        };
        event_loop.reregister(Box::new(next_handler)).unwrap();
        Ok(())
    }
}


struct ProxyServerResponseHandler {
    local_token: Token,
    local_conn: TcpStream,
    remote_token: Token,
    remote_conn: TcpStream,
    transformer: Box<dyn TransformerUnit>,
    client_transformer: Option<Box<dyn TransformerUnit>>,
    tunnel_meta: TunnelMeta,
}

impl EventHandler for ProxyServerResponseHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        // let tunnel = &mut self.tunnel;
        registry.register(&mut self.local_conn, self.local_token, Interest::WRITABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        // let tunnel = &mut self.tunnel;
        registry.reregister(&mut self.local_conn, self.local_token, Interest::WRITABLE)
    }

    fn handle(mut self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_writable() {
            // response 200 if using http tunnel
            if !self.tunnel_meta.http_forward_mode {
                let message = "HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes();
                let conn = &mut self.local_conn;
                if let Err(e) = conn.write(message) {
                    wd_log::log_warn_ln!("ProxyServerResponseHandler # fail to write {:?}", e);
                    return;
                }
            }

            let mut tunnel_transformers = Vec::new();
            tunnel_transformers.push(self.transformer);
            if let Some(t) = self.client_transformer {
                tunnel_transformers.push(t);
            }
            let tunnel_cell = Rc::new(RefCell::new(EstablishedTunnel::new(
                tunnel_transformers,
                self.tunnel_meta,
                self.local_conn,
                self.local_token,
                self.remote_conn,
                self.remote_token,
                None,
            )));
            EstablishedTunnel::process_conn_event(tunnel_cell, event_loop, None, None);
        }
    }
}
