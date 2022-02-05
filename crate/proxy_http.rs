use std::io;
use std::io::{Read, Write};
use std::rc::Rc;
use std::cell::RefCell;
use mio::{Interest, Token};
use mio::event::{Event, Source};
use mio::net::{TcpListener, TcpStream};
use std::net::{SocketAddr};
use crate::event_loop::{EventHandler, EventLoop};
use crate::http_header_parser::parse_http_header;
use crate::transformer::{TunnelDirectTransformer, TunnelTransformer, TunnelSniomitTransformer};
use crate::configuration::GlobalConfiguration;


struct IncrementalCounter {
    value: usize,
}

impl IncrementalCounter {
    pub fn new() -> Self {
        Self { value: 256 }
    }

    fn get(&mut self) -> usize {
        self.value += 4;
        return self.value;
    }
}



struct HttpProxyRemote {
    connection: TcpStream,
    token: Token,
    transformer: Rc<RefCell<TunnelSniomitTransformer>>,
}

impl HttpProxyRemote {
    fn from_existed_connection(
        token_id: usize,
        remote_cnt: TcpStream,
        transformer: Rc<RefCell<TunnelSniomitTransformer>>,
    ) -> Self {
        Self {
            connection: remote_cnt,
            token: Token(token_id),
            transformer,
        }
    }
}

impl EventHandler for HttpProxyRemote {
    fn target(&mut self) -> (&mut dyn Source, Token, Interest) {
        (&mut self.connection, self.token, Interest::WRITABLE | Interest::READABLE)
    }

    fn handle(mut self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        // println!("HttpProxyRemote handler");
        if event.is_writable() {
            match (self.transformer.borrow_mut()).transmit_read(&mut self.connection) {
                Ok(Some(n)) => {
                    if n == 0 {
                        println!("HttpProxyRemote : write zero byte and end listening");
                        return;
                    } else {
                        // println!("HttpProxyRemote : Write data into buffer : Done {} bytes.", n);
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    println!("HttpProxyRemote : Write data into buffer : {:?}", e);
                    return;
                }
            }
        }
        if event.is_readable() {
            match self.transformer.borrow_mut().receive_write(&mut self.connection) {
                Ok(Some(n)) => {
                    if n == 0 {
                        println!("HttpProxyRemote : remote closed.");
                        return;
                    } else {
                        // println!("HttpProxyRemote : Read into buffer : done {} bytes.", n);
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    println!("HttpProxyRemote : Read into buffer : {:?}", e);
                    return;
                }
            }
        }
        match event_loop.reregister(self) {
            Ok(_) => {}
            Err(e) => {
                println!("HttpProxyRemote : Reregister: Fail {:?}", e);
            }
        }
    }
}


enum TunnelStatus {
    Waiting,
    Handshaking(Rc<RefCell<TunnelSniomitTransformer>>),
    Transfering(Rc<RefCell<TunnelSniomitTransformer>>),
}

struct HttpProxyClient {
    connection: TcpStream,
    token: Token,
    buffer_read: Vec<u8>,
    // buffer_write: Vec<u8>,
    tunnel: TunnelStatus,
    global_configuration: Rc<GlobalConfiguration>,
}

impl HttpProxyClient {
    pub fn from_existed_source(token_id: usize, connection: TcpStream,
        global_configuration: Rc<GlobalConfiguration>) -> Self {
        HttpProxyClient {
            connection,
            token: Token(token_id),
            buffer_read: vec![0; 4096],
            // buffer_write: Vec::new(),
            tunnel: TunnelStatus::Waiting,
            global_configuration,
        }
    }
}

impl EventHandler for HttpProxyClient {
    fn target(&mut self) -> (&mut dyn Source, Token, Interest) {
        (&mut self.connection, self.token, Interest::READABLE | Interest::WRITABLE)
    }

    fn handle(mut self: Box<Self>, evt: &Event, event_loop: &mut EventLoop) {
        // println!("HttpProxyClient handler");
        if evt.is_readable() {
            match self.tunnel {
                TunnelStatus::Waiting => {
                    // let notify_client_failure = |msg: &str| {
                    //     self.tunnel = TunnelStatus::Fail;
                    //     self.connection.write("123456".as_bytes());
                    //     return;
                    // };

                    let cnt = &mut self.connection;
                    match cnt.read(&mut self.buffer_read) {
                        Ok(0) => {
                            // println!("Client: Connection closed.");
                            return;
                        }
                        Ok(_) => {
                            let parse_result = parse_http_header(&self.buffer_read);
                            if parse_result.is_none() {
                                let msg = "Invalid http header.";
                                println!("Client : Waiting : {} -> is closing client", msg);
                                self.tunnel = TunnelStatus::Waiting;
                                // notify_client_failure(msg);
                                return;
                            }

                            let (_, request_headers) = parse_result.unwrap();
                            // println!("Remote host address: {}", request_headers[":path"]);
                            // let remote_addr_result = request_headers[":path"].parse();
                            // if remote_addr_result.is_err() {
                            //     // println!("Parse error: {:?}", remote_addr_result.unwrap_err());
                            //     let msg = "Invalid remote host uri";
                            //     // notify_client_failure(msg);
                            //     println!("Client : Waiting : {} -> is closing client", msg);
                            //     return;
                            // }

                            let connect_host_name = request_headers[":path"].clone();
                            let connect_server_name = request_headers[":path"].split(':').next().unwrap();
                            let connect_result = std::net::TcpStream::connect(&connect_host_name);
                            if connect_result.is_err() {
                                // let msg = "Fail to connect to remote host.";
                                // notify_client_failure(msg);
                                println!("Client : Establish tunnel {:?} : {:?}",
                                    &connect_server_name, connect_result);
                                return;
                            }
                            let connect = connect_result.unwrap();

                            // construct the tunnel
                            let tunnel_transformer_result = match connect.peer_addr() {
                                // io::net::SocketAddr::V4(_, 443) =>
                                //     Rc::new(RefCell::new(TunnelSniomitTransformer::new(self.global_configuration))),
                                // io::net::SocketAddr::V6(_, 443) =>
                                //     Rc::new(RefCell::new(TunnelSniomitTransformer::new(self.global_configuration))),
                                _ => TunnelSniomitTransformer::new(
                                    Rc::clone(&self.global_configuration),
                                    &connect_server_name,
                                ),
                            };

                            if tunnel_transformer_result.is_err() {
                                println!(
                                    "Fail to create transformer",
                                    // tunnel_transformer_result.unwrap_err().description()
                                );
                                return;
                            }
                            let tunnel_transformer = Rc::new(RefCell::new(tunnel_transformer_result.unwrap()));

                            self.tunnel = TunnelStatus::Handshaking(Rc::clone(&tunnel_transformer));
                            let remote_token_id = self.token.0 | 1;
                            let remote = HttpProxyRemote::from_existed_connection(
                                remote_token_id,
                                TcpStream::from_std(connect),
                                Rc::clone(&tunnel_transformer),
                            );
                            let register_result = event_loop.register(Box::new(remote));
                            if register_result.is_err() {
                                println!("Remote : register : Fail");
                                return;
                            }
                            // println!("WAHAHAH...");
                        }
                        Err(e) => {
                            println!("Client : Read : {:?}", e);
                            return;
                        }
                    }
                }
                TunnelStatus::Handshaking(ref _r) => {}
                TunnelStatus::Transfering(ref tunnel_transformer) => {
                    let connection = &mut self.connection;
                    match tunnel_transformer.borrow_mut().transmit_write(connection) {
                        Ok(Some(n)) => {
                            if n == 0 {
                                println!("Client : Tunnel : closing connection (by local).");
                                return;
                            } else {
                                // println!("Client : Tunnel : move {} bytes to remote buffer.", n);
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            println!("Client : Tunnel : fail to read. {:?}", e);
                            return;
                        }
                    }
                }
            }
        }

        if evt.is_writable() {
            match self.tunnel {
                TunnelStatus::Waiting => {}
                TunnelStatus::Handshaking(ref tunnel_transformer) => {
                    let response = "HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes();
                    // let _ = tunnel_transformer.borrow_mut().receive_write(&mut response);
                    if self.connection.write(response).is_err() {
                        println!("Client : Handshaking : fail to write.");
                        return;
                    }
                    self.tunnel = TunnelStatus::Transfering(Rc::clone(tunnel_transformer));
                }
                TunnelStatus::Transfering(ref tunnel_transformer) => {
                    let mut buf_ref = tunnel_transformer.borrow_mut();
                    match buf_ref.receive_read(&mut self.connection) {
                        Ok(Some(n)) => {
                            if n == 0 {
                                println!("Client : Tunnel : closing connection (by remote)");
                                return;
                            } else {
                                // println!("Client : Tunnel : sent {} bytes", n);
                            }
                        }
                        Ok(None) => {}
                        Err(_) => {
                            println!("Client : Tunnel : fail to write.");
                            return;
                        }
                    }
                }
            }
        }

        match event_loop.reregister(self) {
            Ok(_) => {}
            Err(e) => {
                println!("Client Reregister: Fail. {:?}", e);
            }
        }
    }
}


pub struct HttpProxyServer {
    listener: TcpListener,
    token: Token,
    counter: IncrementalCounter,
    global_configuration: Rc<GlobalConfiguration>,
}


impl EventHandler for HttpProxyServer {
    fn target(&mut self) -> (&mut dyn Source, Token, Interest) {
        (&mut self.listener, self.token, Interest::READABLE)
    }

    fn handle(mut self: Box<Self>, _evt: &Event, event_loop: &mut EventLoop) {
        // println!("Http Proxy Server handler.");
        match self.listener.accept() {
            Ok((sock, _address)) => {
                let client_token_id = self.as_mut().counter.get();
                let client = HttpProxyClient::from_existed_source(client_token_id, sock, Rc::clone(&self.global_configuration));
                match event_loop.register(Box::new(client)) {
                    Ok(_tok) => {
                        // println!("Listening the incoming connection from {}", address);
                    }
                    Err(_) => {
                        println!("Fail to register new client connection");
                    }
                }
            }
            Err(e) => {
                println!("Fail to accept the incoming connection. ({:?})", e);
            }
        }
        match event_loop.reregister(self) {
            Ok(_) => {
                // println!("Server Register : Ok.");
            }
            Err(e) => {
                println!("Server Register : Fail. {:?}", e);
            }
        }
    }
}

impl HttpProxyServer {
    pub fn new(address: SocketAddr, conf: Rc<GlobalConfiguration>) -> io::Result<HttpProxyServer> {
        let listener = match TcpListener::bind(address) {
            Ok(listener) => listener,
            Err(e) => { return Err(e) },
        };
        Ok(HttpProxyServer {
            listener: listener,
            token: Token(17),
            counter: IncrementalCounter::new(),
            global_configuration: conf,
        })
    }
}

