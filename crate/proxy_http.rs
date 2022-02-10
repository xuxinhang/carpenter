use std::io;
use std::io::{Read, Write};
use std::rc::Rc;
use std::cell::RefCell;
use mio::{Interest, Token};
use mio::event::{Event};
use mio::net::{TcpListener, TcpStream};
use std::net::{SocketAddr, Shutdown, ToSocketAddrs};
use crate::event_loop::{EventHandler, EventLoop, EventRegistryIntf};
use crate::http_header_parser::parse_http_header;
use crate::transformer::{TransferResult, TunnelTransformer, TunnelSniomitTransformer};
use crate::configuration::GlobalConfiguration;



struct IncrementalCounter {
    value: usize,
}

impl IncrementalCounter {
    pub fn new() -> Self {
        Self { value: 256 }
    }

    fn get(&mut self) -> usize {
        self.value += 8;
        return self.value;
    }
}



pub struct HttpProxyServer {
    listener: TcpListener,
    token: Token,
    counter: IncrementalCounter,
    global_configuration: Rc<GlobalConfiguration>,
}

impl HttpProxyServer {
    pub fn new(
        address: SocketAddr,
        global_configuration: Rc<GlobalConfiguration>,
    ) -> io::Result<Self> {
        let result = TcpListener::bind(address);
        if result.is_err() {
            return Err(result.unwrap_err());
        }
        let listener = result.unwrap();

        Ok(HttpProxyServer {
            listener,
            token: Token(17),
            counter: IncrementalCounter::new(),
            global_configuration,
        })
    }

    pub fn initial_register(self, event_loop: &mut EventLoop) -> io::Result<()> {
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

    fn handle(mut self: Box<Self>, _evt: &Event, event_loop: &mut EventLoop) {
        match self.listener.accept() {
            Ok((conn, _address)) => {
                let token_id = self.as_mut().counter.get();
                let client = ProxyRequestHandler {
                    global_configuration: self.global_configuration.clone(),
                    token: Token(token_id),
                    client: ClientShakingConnection::from_connection(conn),
                };
                if let Err(e) = event_loop.register(Box::new(client)) {
                    wd_log::log_warn_ln!("HttpProxyServer # Fail to register the new client connection {:?}", e);
                }
                // wd_log::log_debug_ln!("Listening the incoming connection from {}", _address);
            }
            Err(e) => {
                wd_log::log_warn_ln!("HttpProxyServer # Fail to accept the incoming connection. ({:?})", e);
            }
        }

        event_loop.reregister(self).unwrap();
    }
}



struct ClientShakingConnection {
    client_conn: TcpStream,
}

impl ClientShakingConnection {
    fn from_connection(conn: TcpStream) -> Self {
        Self { client_conn: conn }
    }
}

struct Tunnel {
    local_conn: TcpStream,
    remote_conn: TcpStream,
    transformer: TunnelSniomitTransformer,
    local_token: Token,
    remote_token: Token,
}

impl Tunnel {
    fn from_connection(
        local_token: Token,
        local_conn: TcpStream,
        remote_token: Token,
        remote_conn: TcpStream,
        transformer: TunnelSniomitTransformer,
    ) -> Self {
        Self {
            local_conn,
            remote_conn,
            transformer,
            local_token,
            remote_token,
        }
    }

    fn receive_pull(&mut self) -> TransferResult {
        self.transformer.receive_write(&mut self.remote_conn)
    }

    fn receive_push(&mut self) -> TransferResult {
        self.transformer.receive_read(&mut self.local_conn)
    }

    fn transmit_pull(&mut self) -> TransferResult {
        self.transformer.transmit_write(&mut self.local_conn)
    }

    fn transmit_push(&mut self) -> TransferResult {
        self.transformer.transmit_read(&mut self.remote_conn)
    }
}



struct ProxyRequestHandler {
    global_configuration: Rc<GlobalConfiguration>,
    token: Token,
    client: ClientShakingConnection,
}

impl EventHandler for ProxyRequestHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.client.client_conn, self.token, Interest::READABLE)
    }

    fn handle(mut self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_readable() {
            let conn = &mut self.client.client_conn;

            let mut buf = vec![0u8; 4*1024*1024];
            let result = conn.peek(&mut buf);
            if result.is_err() {
                println!("ProxyRequestHandler # peek error.");
                return;
            }

            let result = parse_http_header(&buf);
            if result.is_none() {
                wd_log::log_warn_ln!("ProxyRequestHandler # Invalid HTTP message.");
                return;
            }
            let (header_length, msg_headers) = result.unwrap();
            let mut trash = vec![0; header_length];
            let result = conn.read(&mut trash);
            // println!("HEADER {}", String::from_utf8(trash).unwrap());

            if result.is_err() {
                println!("ProxyRequestHandler # read error.");
                return;
            }

            let request_host = msg_headers[":path"].clone();
            let request_hostname = request_host.split(':').next().unwrap();

            let result = request_host.to_socket_addrs();
            if result.is_err() {
                wd_log::log_warn_ln!("ProxyRequestHandler # Cannot find DNS Name {:?}", request_host);
                return;
            }

            let result = TcpStream::connect(result.unwrap().next().unwrap());
            if result.is_err() {
                wd_log::log_warn_ln!("ProxyRequestHandler # TcpStream::connect error");
                return;
            }
            let peer_conn = result.unwrap();

            let transformer = TunnelSniomitTransformer::new(
                self.global_configuration.clone(),
                request_hostname,
                request_hostname,
            ).unwrap();
            let tunnel = Tunnel::from_connection(
                Token(self.token.0 + 1), self.client.client_conn,
                Token(self.token.0 + 2), peer_conn,
                transformer,
            );
            let next_handler = ProxyResponseHandler {
                global_configuration: self.global_configuration.clone(),
                tunnel,
            };
            if let Err(e) = event_loop.reregister(Box::new(next_handler)) {
                println!("ProxyRequestHandler # event_loop.register {:?}", e);
            }
        }
    }
}


struct ProxyResponseHandler {
    global_configuration: Rc<GlobalConfiguration>,
    tunnel: Tunnel,
}

impl EventHandler for ProxyResponseHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut self.tunnel;
        registry.register(&mut tunnel.local_conn, tunnel.local_token, Interest::WRITABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut self.tunnel;
        registry.reregister(&mut tunnel.local_conn, tunnel.local_token, Interest::WRITABLE)
    }

    fn handle(mut self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_writable() {
            let conn = &mut self.tunnel.local_conn;
            let message = "HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes();
            match conn.write(message) {
                Ok(_) => {
                    let tunnel = self.tunnel;
                    let tunnel_ptr = Rc::new(RefCell::new(tunnel));

                    if let Err(e) = event_loop.reregister(Box::new(ProxyTransferLocalReadableHandler {
                        tunnel: tunnel_ptr.clone(),
                    })) {
                        println!("ProxyResponseHandler # event_loop.register {:?}", e);
                    }
                    if let Err(e) = event_loop.register(Box::new(ProxyTransferRemoteReadableHandler {
                        tunnel: tunnel_ptr.clone(),
                    })) {
                        println!("ProxyResponseHandler # event_loop.register {:?}", e);
                    }
                    if let Err(e) = event_loop.reregister(Box::new(ProxyTransferLocalWritableHandler {
                        tunnel: tunnel_ptr.clone(),
                    })) {
                        println!("ProxyResponseHandler # event_loop.register {:?}", e);
                    }
                    if let Err(e) = event_loop.reregister(Box::new(ProxyTransferRemoteWritableHandler {
                        tunnel: tunnel_ptr.clone(),
                    })) {
                        println!("ProxyResponseHandler # event_loop.register {:?}", e);
                    }
                }
                Err(e) => {
                    wd_log::log_warn_ln!("ProxyResponseHandler # fail to write {:?}", e);
                    return;
                }
            }
        }
    }
}


struct ProxyTransferLocalReadableHandler {
    tunnel: Rc<RefCell<Tunnel>>,
}

impl EventHandler for ProxyTransferLocalReadableHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.register(&mut tunnel.local_conn, tunnel.local_token, Interest::READABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.reregister(&mut tunnel.local_conn, tunnel.local_token, Interest::READABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        let mut reregister_remote_writable_flag = false;
        let mut mark_reregister_remote_writable = || { reregister_remote_writable_flag = true; };
        let mut reregister_local_writable_flag = false;
        let mut mark_reregister_local_writable = || { reregister_local_writable_flag = true; };
        let mut reregister_local_readable_flag = false;
        let mut mark_reregister_local_readable = || { reregister_local_readable_flag = true; };

        if event.is_readable() {
            // println!("ProxyTransferLocalReadableHandler # handle");
            let tunnel_mut = &mut * self.tunnel.borrow_mut();
            let result = tunnel_mut.transmit_pull();
            let conn = &mut tunnel_mut.local_conn;
            match result {
                TransferResult::Data(0) => {
                    // println!("ProxyTransferLocalReadableHandler # transmit pull {} bytes", 0);
                    mark_reregister_local_readable();
                }
                TransferResult::Data(_n) => {
                    // println!("ProxyTransferLocalReadableHandler # transmit pull {} bytes", _n);
                    mark_reregister_local_readable();
                    mark_reregister_local_writable();
                    mark_reregister_remote_writable();
                    // IMPORTANT: We also need to register local-side socket writable
                    //            because the local-side tls connection may be handshaking
                }
                TransferResult::End(_) => {
                    // println!("ProxyTransferLocalReadableHandler # transmit end");
                    let _ = conn.shutdown(Shutdown::Read);
                    mark_reregister_remote_writable();
                }
                TransferResult::IoError(e) => {
                    wd_log::log_warn_ln!("ProxyTransferLocalReadableHandler # transmit_write error {:?}", e);
                    let _ = conn.shutdown(Shutdown::Read);
                }
                TransferResult::TlsError(e) => {
                    wd_log::log_warn_ln!("ProxyTransferLocalReadableHandler # transmit_write error {:?}", e);
                    let _ = conn.shutdown(Shutdown::Read);
                }
            }
        }

        if reregister_remote_writable_flag {
            if let Err(e) = event_loop.reregister(Box::new(ProxyTransferRemoteWritableHandler {
                tunnel: Rc::clone(&self.tunnel),
            })) {
                println!("ProxyTransferLocalReadableHandler # event_loop.register {:?}", e);
            }
        }
        if reregister_local_writable_flag {
            if let Err(e) = event_loop.reregister(Box::new(ProxyTransferLocalWritableHandler {
                tunnel: Rc::clone(&self.tunnel),
            })) {
                println!("ProxyTransferLocalReadableHandler # event_loop.register {:?}", e);
            }
        }
        if reregister_local_readable_flag {
            if let Err(e) = event_loop.reregister(self) {
                println!("ProxyTransferLocalReadableHandler # event_loop.register {:?}", e);
            }
        }
    }
}


struct ProxyTransferRemoteReadableHandler {
    tunnel: Rc<RefCell<Tunnel>>,
}

impl EventHandler for ProxyTransferRemoteReadableHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.register(&mut tunnel.remote_conn, tunnel.remote_token, Interest::READABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.reregister(&mut tunnel.remote_conn, tunnel.remote_token, Interest::READABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        let mut reregister_local_writable_flag = false;
        let mut mark_reregister_local_writable = || { reregister_local_writable_flag = true; };
        let mut reregister_remote_writable_flag = false;
        let mut mark_reregister_remote_writable = || { reregister_remote_writable_flag = true; };
        let mut reregister_remote_readable_flag = false;
        let mut mark_reregister_remote_readable = || { reregister_remote_readable_flag = true; };

        if event.is_readable() {
            // println!("ProxyTransferRemoteReadableHandler # handle");
            let tunnel_mut = &mut * self.tunnel.borrow_mut();
            let result = tunnel_mut.receive_pull();
            let conn = &mut tunnel_mut.remote_conn;
            match result {
                TransferResult::Data(0) => {
                    // println!("ProxyTransferRemoteReadableHandler # transmit pull {} bytes", 0);
                    mark_reregister_remote_readable();
                }
                TransferResult::Data(_n) => {
                    // println!("ProxyTransferRemoteReadableHandler # transmit pull {} bytes", _n);
                    mark_reregister_remote_readable();
                    mark_reregister_local_writable();
                    mark_reregister_remote_writable();
                    // IMPORTANT: We also need to register remote-side socket writable
                    //            because the remote-side tls connection may be handshaking
                }
                TransferResult::End(_) => {
                    let _ = conn.shutdown(Shutdown::Read);
                    mark_reregister_local_writable();
                    mark_reregister_remote_writable();
                }
                TransferResult::IoError(e) => {
                    wd_log::log_warn_ln!("ProxyTransferRemoteReadableHandler # receive_write error {:?}", e);
                    let _ = conn.shutdown(Shutdown::Read);
                }
                TransferResult::TlsError(e) => {
                    wd_log::log_warn_ln!("ProxyTransferRemoteReadableHandler # receive_write error {:?}", e);
                    let _ = conn.shutdown(Shutdown::Read);
                }
            }
        }

        if reregister_local_writable_flag {
            if let Err(e) = event_loop.reregister(Box::new(ProxyTransferLocalWritableHandler {
                tunnel: Rc::clone(&self.tunnel),
            })) {
                println!("ProxyTransferRemoteReadableHandler # event_loop.register {:?}" ,e);
            }
        }
        if reregister_remote_writable_flag {
            if let Err(e) = event_loop.reregister(Box::new(ProxyTransferRemoteWritableHandler {
                tunnel: Rc::clone(&self.tunnel),
            })) {
                println!("ProxyTransferRemoteReadableHandler # event_loop.register {:?}" ,e);
            }
        }
        if reregister_remote_readable_flag {
            if let Err(e) = event_loop.reregister(self) {
                println!("ProxyTransferRemoteReadableHandler # event_loop.register {:?}", e);
            }
        }
    }
}


struct ProxyTransferRemoteWritableHandler {
    tunnel: Rc<RefCell<Tunnel>>,
}

impl EventHandler for ProxyTransferRemoteWritableHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.register(&mut tunnel.remote_conn, tunnel.remote_token, Interest::WRITABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.reregister(&mut tunnel.remote_conn, tunnel.remote_token, Interest::WRITABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        let mut reregister_flag = false;
        let mut mark_reregister = || { reregister_flag = true; };

        if event.is_writable() {
            // println!("ProxyTransferRemoteWritableHandler # handle");
            let tunnel_mut = &mut * self.tunnel.borrow_mut();
            let result = tunnel_mut.transmit_push();
            let conn = &mut tunnel_mut.remote_conn;
            match result {
                TransferResult::Data(0) => {
                    // println!("ProxyTransferRemoteWritableHandler # transfer {} bytes.", 0);
                }
                TransferResult::Data(_n) => {
                    // println!("ProxyTransferRemoteWritableHandler # transfer {} bytes.", _n);
                    mark_reregister();
                }
                TransferResult::End(_) => {
                    // wd_log::log_debug_ln!("HttpProxyRemote : write zero byte and end listening");
                    let _ = conn.shutdown(Shutdown::Write);
                }
                TransferResult::IoError(e) => {
                    wd_log::log_warn_ln!("ProxyTransferRemoteWritableHandler # transmit_push Error {:?}", e);
                    let _ = conn.shutdown(Shutdown::Write);
                }
                TransferResult::TlsError(e) => {
                    wd_log::log_warn_ln!("ProxyTransferRemoteWritableHandler # transmit_push Error {:?}", e);
                    let _ = conn.shutdown(Shutdown::Write);
                }
            }
        }

        if reregister_flag {
            if let Err(e) = event_loop.reregister(self) {
                println!("ProxyTransferRemoteWritableHandler # event_loop.register {:?}", e);
            }
        }
    }
}


struct ProxyTransferLocalWritableHandler {
    tunnel: Rc<RefCell<Tunnel>>,
}

impl EventHandler for ProxyTransferLocalWritableHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.register(&mut tunnel.local_conn, tunnel.local_token, Interest::WRITABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.reregister(&mut tunnel.local_conn, tunnel.local_token, Interest::WRITABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        let mut reregister_flag = false;
        let mut mark_reregister = || { reregister_flag = true; };

        if event.is_writable() {
            // println!("ProxyTransferLocalWritableHandler # handle");
            let tunnel_mut = &mut * self.tunnel.borrow_mut();
            let result = tunnel_mut.receive_push();
            let conn = &mut tunnel_mut.remote_conn;
            match result {
                TransferResult::Data(0) => {}
                TransferResult::Data(_) => {
                    mark_reregister();
                }
                TransferResult::End(_) => {
                    // wd_log::log_debug_ln!("ProxyTransferLocalWritableHandler # receive_read End");
                    let _ = conn.shutdown(Shutdown::Write);
                }
                TransferResult::IoError(e) => {
                    wd_log::log_warn_ln!("ProxyTransferLocalWritableHandler # receive_read Error {:?}", e);
                    let _ = conn.shutdown(Shutdown::Write);
                }
                TransferResult::TlsError(e) => {
                    wd_log::log_warn_ln!("ProxyTransferLocalWritableHandler # receive_read Error {:?}", e);
                    let _ = conn.shutdown(Shutdown::Write);
                }
            }
        }

        if reregister_flag {
            if event_loop.reregister(self).is_err() {
                println!("ProxyTransferLocalWritableHandler # event_loop.register");
            }
        }
    }
}
