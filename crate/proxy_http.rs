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
                match event_loop.register(Box::new(client)) {
                    Ok(_) => {
                        wd_log::log_debug_ln!("Listening the incoming connection from {}", _address);
                    }
                    Err(_) => {
                        wd_log::log_debug_ln!("Fail to register new client connection");
                    }
                }
            }
            Err(e) => {
                wd_log::log_debug_ln!("Fail to accept the incoming connection. ({:?})", e);
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
                println!("HttpProxyShaker # peek error.");
                return;
            }

            let result = parse_http_header(&buf);
            if result.is_none() {
                println!("HttpProxyShaker # Invalid HTTP message.");
                return;
            }
            let (header_length, msg_headers) = result.unwrap();
            let mut trash = vec![0; header_length];
            let result = conn.read(&mut trash);
            // println!("HEADER {}", String::from_utf8(trash).unwrap());

            if result.is_err() {
                println!("HttpProxyShaker # read error.");
                return;
            }

            let request_host = msg_headers[":path"].clone();
            let request_hostname = request_host.split(':').next().unwrap();

            let result = request_host.to_socket_addrs();
            if result.is_err() {
                println!("HttpProxyShaker # Cannot find DNS Name {:?}", request_host);
                return;
            }

            let result = TcpStream::connect(result.unwrap().next().unwrap());
            if result.is_err() {
                println!("ProxyRequestHandler # TcpStream::connect error");
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
                token: Token(self.token.0 + 1),
                tunnel,
            };
            if let Err(e) = event_loop.reregister(Box::new(next_handler)) {
                println!("ProxyRequestHandler Error # event_loop.register {:?}", e);
            }
        }
    }
}


struct ProxyResponseHandler {
    global_configuration: Rc<GlobalConfiguration>,
    token: Token,
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
                    let next_token_base = self.token.0;
                    let tunnel_ptr = Rc::new(RefCell::new(tunnel));

                    if let Err(e) = event_loop.reregister(Box::new(ProxyTransferLocalReadableHandler {
                        token: Token(next_token_base + 1),
                        tunnel: tunnel_ptr.clone(),
                    })) {
                        println!("ProxyResponseHandler # event_loop.register {:?}", e);
                    }
                    if let Err(e) = event_loop.register(Box::new(ProxyTransferRemoteReadableHandler {
                        token: Token(next_token_base + 2),
                        tunnel: tunnel_ptr.clone(),
                    })) {
                        println!("ProxyResponseHandler # event_loop.register {:?}", e);
                    }
                    if let Err(e) = event_loop.reregister(Box::new(ProxyTransferLocalWritableHandler {
                        token: Token(next_token_base + 3),
                        tunnel: tunnel_ptr.clone(),
                    })) {
                        println!("ProxyResponseHandler # event_loop.register {:?}", e);
                    }
                    if let Err(e) = event_loop.reregister(Box::new(ProxyTransferRemoteWritableHandler {
                        token: Token(next_token_base + 4),
                        tunnel: tunnel_ptr.clone(),
                    })) {
                        println!("ProxyResponseHandler # event_loop.register {:?}", e);
                    }
                }
                Err(_) => {
                    wd_log::log_debug_ln!("ProxyResponseHandler: fail to write.");
                    return;
                }
            }
        }
    }
}


struct ProxyTransferLocalReadableHandler {
    token: Token,
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
                    wd_log::log_debug_ln!("ProxyTransferLocalReadableHandler # transmit_write error {:?}", e);
                    let _ = conn.shutdown(Shutdown::Read);
                }
                TransferResult::TlsError(e) => {
                    wd_log::log_debug_ln!("ProxyTransferLocalReadableHandler # transmit_write error {:?}", e);
                    let _ = conn.shutdown(Shutdown::Read);
                }
            }
        }

        if reregister_remote_writable_flag {
            if let Err(e) = event_loop.reregister(Box::new(ProxyTransferRemoteWritableHandler {
                token: Token(self.token.0 - 1 + 4),
                tunnel: Rc::clone(&self.tunnel),
            })) {
                println!("ProxyTransferLocalReadableHandler # event_loop.register {:?}", e);
            }
        }
        if reregister_local_writable_flag {
            if let Err(e) = event_loop.reregister(Box::new(ProxyTransferLocalWritableHandler {
                token: Token(self.token.0 - 1 + 4),
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
    token: Token,
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
                    wd_log::log_debug_ln!("ProxyTransferRemoteReadableHandler # receive_write error {:?}", e);
                    let _ = conn.shutdown(Shutdown::Read);
                }
                TransferResult::TlsError(e) => {
                    wd_log::log_debug_ln!("ProxyTransferRemoteReadableHandler # receive_write error {:?}", e);
                    let _ = conn.shutdown(Shutdown::Read);
                }
            }
        }

        if reregister_local_writable_flag {
            if let Err(e) = event_loop.reregister(Box::new(ProxyTransferLocalWritableHandler {
                token: Token(self.token.0 - 2 + 3),
                tunnel: Rc::clone(&self.tunnel),
            })) {
                println!("ProxyTransferRemoteReadableHandler # event_loop.register {:?}" ,e);
            }
        }
        if reregister_remote_writable_flag {
            if let Err(e) = event_loop.reregister(Box::new(ProxyTransferRemoteWritableHandler {
                token: Token(self.token.0 - 2 + 3),
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
    token: Token,
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
                    println!("ProxyTransferRemoteWritableHandler # transfer {} bytes.", 0);
                    // assert_eq!(tunnel_mut.transformer.transmit_plaintext_buffer.len(), 0);
                    // mark_reregister();
                }
                TransferResult::Data(n) => {
                    println!("ProxyTransferRemoteWritableHandler # transfer {} bytes.", n);
                    mark_reregister();
                }
                TransferResult::End(_) => {
                    wd_log::log_debug_ln!("HttpProxyRemote : write zero byte and end listening");
                    let _ = conn.shutdown(Shutdown::Write);
                }
                TransferResult::IoError(e) => {
                    wd_log::log_debug_ln!("HttpProxyRemote : Write data into buffer : {:?}", e);
                    let _ = conn.shutdown(Shutdown::Write);
                }
                TransferResult::TlsError(e) => {
                    wd_log::log_debug_ln!("HttpProxyRemote : Write data into buffer : {:?}", e);
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
    token: Token,
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
                TransferResult::Data(0) => {
                    // nothing
                    // mark_reregister();
                }
                TransferResult::Data(_) => {
                    mark_reregister();
                }
                TransferResult::End(_) => {
                    // wd_log::log_debug_ln!("ProxyTransferLocalWritableHandler # receive_read End");
                    let _ = conn.shutdown(Shutdown::Write);
                }
                TransferResult::IoError(e) => {
                    wd_log::log_debug_ln!("ProxyTransferLocalWritableHandler # receive_read Error {:?}", e);
                    let _ = conn.shutdown(Shutdown::Write);
                }
                TransferResult::TlsError(e) => {
                    wd_log::log_debug_ln!("ProxyTransferLocalWritableHandler # receive_read Error {:?}", e);
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






// struct HttpProxyRemote {
//     connection: TcpStream,
//     token: Token,
//     transformer: Rc<RefCell<TunnelSniomitTransformer>>,
//     connection_state_read: bool,
//     connection_state_write: bool,
// }

// impl HttpProxyRemote {
//     fn from_existed_connection(
//         token_id: usize,
//         remote_cnt: TcpStream,
//         transformer: Rc<RefCell<TunnelSniomitTransformer>>,
//     ) -> Self {
//         Self {
//             connection: remote_cnt,
//             token: Token(token_id),
//             transformer,
//             connection_state_read: true,
//             connection_state_write: true,
//         }
//     }
// }

// impl EventHandler for HttpProxyRemote {
//     fn target(&mut self) -> (&mut dyn Source, Token, Interest) {
//         let interest = Interest::READABLE | Interest::WRITABLE;
//         (&mut self.connection, self.token, interest)
//     }

//     fn handle(mut self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
//         // println!("HttpProxyRemote handler");
//         let mut need_reregister = false;
//         let mut mark_reregister = || { need_reregister = true; };

//         if event.is_writable() {
//             match (self.transformer.borrow_mut()).transmit_read(&mut self.connection) {
//                 TransferResult::Data(_n) => {
//                     // println!("HttpProxyRemote : send {} bytes.", _n);
//                     mark_reregister();
//                 }
//                 TransferResult::End(_) => {
//                     wd_log::log_debug_ln!("HttpProxyRemote : write zero byte and end listening");
//                     let _ = self.connection.shutdown(Shutdown::Write);
//                     self.connection_state_write = false;
//                 }
//                 TransferResult::Error => {
//                     wd_log::log_debug_ln!("HttpProxyRemote : Write data into buffer : {:?}", "");
//                     let _ = self.connection.shutdown(Shutdown::Write);
//                     self.connection_state_write = false;
//                 }
//             }
//         }

//         if event.is_readable() {
//             match self.transformer.borrow_mut().receive_write(&mut self.connection) {
//                 TransferResult::Data(_n) => {
//                     // println!("HttpProxyRemote : received {} bytes.", _n);
//                     mark_reregister();
//                 }
//                 TransferResult::End(_) => {
//                     wd_log::log_debug_ln!("HttpProxyRemote : remote closed.");
//                     let _ = self.connection.shutdown(Shutdown::Read);
//                     self.connection_state_read = false;
//                 }
//                 TransferResult::Error => {
//                     wd_log::log_debug_ln!("HttpProxyRemote : Read into buffer : {:?}", "e");
//                     let _ = self.connection.shutdown(Shutdown::Read);
//                     self.connection_state_read = false;
//                 }
//             }
//         }

//         if self.connection_state_read && self.connection_state_write {
//             event_loop.reregisteri(self, Interest::READABLE | Interest::WRITABLE).unwrap();
//         } else if self.connection_state_read {
//             event_loop.reregisteri(self, Interest::READABLE).unwrap();
//         } else if self.connection_state_write {
//             event_loop.reregisteri(self, Interest::WRITABLE).unwrap();
//         } else {
//             // nothing
//         }
//     }
// }


// enum TunnelStatus {
//     Waiting,
//     Handshaking(Rc<RefCell<TunnelSniomitTransformer>>),
//     Transfering(Rc<RefCell<TunnelSniomitTransformer>>),
// }

// struct HttpProxyClient {
//     connection: TcpStream,
//     token: Token,
//     buffer_read: Vec<u8>,
//     // buffer_write: Vec<u8>,
//     tunnel: TunnelStatus,
//     global_configuration: Rc<GlobalConfiguration>,
//     connection_state_read: bool,
//     connection_state_write: bool,
// }

// impl HttpProxyClient {
//     pub fn from_existed_source(token_id: usize, connection: TcpStream,
//         global_configuration: Rc<GlobalConfiguration>) -> Self {
//         HttpProxyClient {
//             connection,
//             token: Token(token_id),
//             buffer_read: vec![0; 4096],
//             // buffer_write: Vec::new(),
//             tunnel: TunnelStatus::Waiting,
//             global_configuration,
//             connection_state_read: true,
//             connection_state_write: true,
//         }
//     }
// }

// impl EventHandler for HttpProxyClient {
//     fn target(&mut self) -> (&mut dyn Source, Token, Interest) {
//         let interest = Interest::READABLE | Interest::WRITABLE;
//         (&mut self.connection, self.token, interest)
//     }

//     fn handle(mut self: Box<Self>, evt: &Event, event_loop: &mut EventLoop) {
//         // println!("HttpProxyClient handler");
//         let mut need_reregister = false;
//         let mut mark_reregister = || { need_reregister = true; };

//         if evt.is_readable() {
//             match self.tunnel {
//                 TunnelStatus::Waiting => {
//                     // let notify_client_failure = |msg: &str| {
//                     //     self.tunnel = TunnelStatus::Fail;
//                     //     self.connection.write("123456".as_bytes());
//                     //     return;
//                     // };

//                     let cnt = &mut self.connection;
//                     match cnt.read(&mut self.buffer_read) {
//                         Ok(0) => {
//                             println!("Client: Connection closed.");
//                             return;
//                         }
//                         Ok(_) => {
//                             let parse_result = parse_http_header(&self.buffer_read);
//                             if parse_result.is_none() {
//                                 let msg = "Invalid http header.";
//                                 println!("Client : Waiting : {} -> is closing client", msg);
//                                 self.tunnel = TunnelStatus::Waiting;
//                                 // notify_client_failure(msg);
//                                 return;
//                             }

//                             let (_, request_headers) = parse_result.unwrap();
//                             // println!("Remote host address: {}", request_headers[":path"]);
//                             // let remote_addr_result = request_headers[":path"].parse();
//                             // if remote_addr_result.is_err() {
//                             //     // println!("Parse error: {:?}", remote_addr_result.unwrap_err());
//                             //     let msg = "Invalid remote host uri";
//                             //     // notify_client_failure(msg);
//                             //     println!("Client : Waiting : {} -> is closing client", msg);
//                             //     return;
//                             // }

//                             let connect_host_name = request_headers[":path"].clone();
//                             let connect_server_name = request_headers[":path"].split(':').next().unwrap();
//                             println!("HttpProxyClient Waiting1");
//                             // let connect_result = std::net::TcpStream::connect(&connect_host_name);
//                             let ip_addr_result = connect_host_name.to_socket_addrs();
//                             if ip_addr_result.is_err() {
//                                 wd_log::log_error_ln!("Fail to find DNS record");
//                                 return;
//                             }
//                             let connect_result = TcpStream::connect(ip_addr_result.unwrap().next().unwrap());
//                             println!("HttpProxyClient Waiting2");
//                             if connect_result.is_err() {
//                                 // let msg = "Fail to connect to remote host.";
//                                 // notify_client_failure(msg);
//                                 println!("Client : Establish tunnel {:?} : {:?}",
//                                     &connect_server_name, connect_result);
//                                 return;
//                             }
//                             let connect = connect_result.unwrap();
//                             let connect_peer_address_string = connect.peer_addr().unwrap().to_string();

//                             // construct the tunnel
//                             let tunnel_transformer_result = match connect.peer_addr() {
//                                 // io::net::SocketAddr::V4(_, 443) =>
//                                 //     Rc::new(RefCell::new(TunnelSniomitTransformer::new(self.global_configuration))),
//                                 // io::net::SocketAddr::V6(_, 443) =>
//                                 //     Rc::new(RefCell::new(TunnelSniomitTransformer::new(self.global_configuration))),
//                                 _ => TunnelSniomitTransformer::new(
//                                     Rc::clone(&self.global_configuration),
//                                     &connect_server_name,
//                                     &connect_peer_address_string,
//                                 ),
//                             };

//                             if tunnel_transformer_result.is_err() {
//                                 wd_log::log_debug_ln!(
//                                     "Fail to create transformer",
//                                     // tunnel_transformer_result.unwrap_err().description()
//                                 );
//                                 return;
//                             }
//                             let tunnel_transformer = Rc::new(RefCell::new(tunnel_transformer_result.unwrap()));

//                             println!("HttpProxyClient Waiting3");
//                             self.tunnel = TunnelStatus::Handshaking(Rc::clone(&tunnel_transformer));
//                             let remote_token_id = self.token.0 | 1;
//                             let remote = HttpProxyRemote::from_existed_connection(
//                                 remote_token_id,
//                                 connect, // TcpStream::from_std(connect),
//                                 Rc::clone(&tunnel_transformer),
//                             );
//                             println!("HttpProxyClient Waiting4");
//                             let register_result = event_loop.register(Box::new(remote));
//                             if register_result.is_err() {
//                                 wd_log::log_debug_ln!("Remote : register : Fail");
//                                 return;
//                             }
//                             println!("HttpProxyClient Waiting5");
//                         }
//                         Err(e) => {
//                             wd_log::log_debug_ln!("Client : Read : {:?}", e);
//                             return;
//                         }
//                     }
//                     mark_reregister();
//                 }
//                 TunnelStatus::Handshaking(ref _r) => {}
//                 TunnelStatus::Transfering(ref tunnel_transformer) => {
//                     let connection = &mut self.connection;
//                     match tunnel_transformer.borrow_mut().transmit_write(connection) {
//                         TransferResult::Data(_n) => {
//                             // println!("HttpProxyClient : Tunnel : send {} bytes.", _n);
//                             mark_reregister();
//                         }
//                         TransferResult::End(_) => {
//                             wd_log::log_debug_ln!("Client : Tunnel : closing connection (by local).");
//                             let _ = connection.shutdown(Shutdown::Read);
//                             self.connection_state_read = false;
//                         }
//                         TransferResult::Error => {
//                             wd_log::log_debug_ln!("Client : Tunnel : fail to read. {:?}", "e");
//                             let _ = connection.shutdown(Shutdown::Read);
//                             self.connection_state_read = false;
//                         }
//                     }
//                 }
//             }
//         }

//         if evt.is_writable() {
//             match self.tunnel {
//                 TunnelStatus::Waiting => {}
//                 TunnelStatus::Handshaking(ref tunnel_transformer) => {
//                     let response = "HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes();
//                     if self.connection.write(response).is_err() {
//                         wd_log::log_debug_ln!("Client : Handshaking : fail to write.");
//                         return;
//                     }
//                     self.tunnel = TunnelStatus::Transfering(Rc::clone(tunnel_transformer));
//                 }
//                 TunnelStatus::Transfering(ref tunnel_transformer) => {
//                     let mut buf_ref = tunnel_transformer.borrow_mut();
//                     match buf_ref.receive_read(&mut self.connection) {
//                         TransferResult::Data(_n) => {
//                             // println!("HttpProxyClient : Tunnel : receive {} bytes", _n);
//                             mark_reregister();
//                         }
//                         TransferResult::End(_) => {
//                             wd_log::log_debug_ln!("HttpProxyClient : Tunnel : closing connection (by remote)");
//                             let _ = self.connection.shutdown(Shutdown::Write);
//                             self.connection_state_write = false;
//                         }
//                         TransferResult::Error => {
//                             wd_log::log_debug_ln!("HttpProxyClient : Tunnel : fail to write.");
//                             let _ = self.connection.shutdown(Shutdown::Write);
//                             self.connection_state_write = false;
//                         }
//                     }
//                 }
//             }
//         }

//         if self.connection_state_read && self.connection_state_write {
//             event_loop.reregisteri(self, Interest::READABLE | Interest::WRITABLE).unwrap();
//         } else if self.connection_state_read {
//             event_loop.reregisteri(self, Interest::READABLE).unwrap();
//         } else if self.connection_state_write {
//             event_loop.reregisteri(self, Interest::WRITABLE).unwrap();
//         } else {
//             // nothing
//         }
//     }
// }


// // pub struct HttpProxyServer {
// //     listener: TcpListener,
// //     token: Token,
// //     counter: IncrementalCounter,
// //     global_configuration: Rc<GlobalConfiguration>,
// // }


// // impl EventHandler for HttpProxyServer {
// //     fn target(&mut self) -> (&mut dyn Source, Token, Interest) {
// //         (&mut self.listener, self.token, Interest::READABLE)
// //     }

// //     fn handle(mut self: Box<Self>, _evt: &Event, event_loop: &mut EventLoop) {
// //         // println!("Http Proxy Server handler.");
// //         match self.listener.accept() {
// //             Ok((sock, _address)) => {
// //                 let client_token_id = self.as_mut().counter.get();
// //                 let client = HttpProxyClient::from_existed_source(client_token_id, sock, Rc::clone(&self.global_configuration));
// //                 match event_loop.register(Box::new(client)) {
// //                     Ok(_) => {
// //                         wd_log::log_error_ln!("Listening the incoming connection from {}", _address);
// //                     }
// //                     Err(_) => {
// //                         wd_log::log_debug_ln!("Fail to register new client connection");
// //                     }
// //                 }
// //             }
// //             Err(e) => {
// //                 wd_log::log_debug_ln!("Fail to accept the incoming connection. ({:?})", e);
// //             }
// //         }

// //         event_loop.reregister(self).unwrap();
// //     }
// // }

// // impl HttpProxyServer {
// //     pub fn new(address: SocketAddr, conf: Rc<GlobalConfiguration>) -> io::Result<HttpProxyServer> {
// //         let listener = match TcpListener::bind(address) {
// //             Ok(listener) => listener,
// //             Err(e) => { return Err(e) },
// //         };
// //         Ok(HttpProxyServer {
// //             listener: listener,
// //             token: Token(17),
// //             counter: IncrementalCounter::new(),
// //             global_configuration: conf,
// //         })
// //     }
// // }

