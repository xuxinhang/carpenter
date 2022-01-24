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


struct TunnelPacketBuffer {
    buf: Vec<Vec<u8>>,
}

impl TunnelPacketBuffer {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> usize {
        let mut accu_size = 0;
        if self.buf.len() <= 64 {
            let b = bytes.to_vec();
            let read_size = b.len();
            accu_size += read_size;
            self.buf.push(b);
        }
        accu_size
    }

    fn read_from(&mut self, sock: &mut impl Read) -> io::Result<Option<usize>> {
        let mut accu_size = 0;
        while self.buf.len() <= 64 {
            let mut b = vec![0; 4096];
            let read_size = sock.read(&mut b)?;
            accu_size += read_size;
            let short_packet = read_size < 4096;
            if short_packet {
                b.truncate(read_size);
            }
            self.buf.push(b);
            if short_packet {
                break;
            }
            break;
        }
        Ok(Some(accu_size))
    }

    fn write_into(&mut self, sock: &mut impl Write) -> io::Result<Option<usize>> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        let mut accu_size = 0;
        while !self.buf.is_empty() {
            let b = self.buf.remove(0);
            let write_size = sock.write(&b)?;
            accu_size += write_size;
            break;
        }
        Ok(Some(accu_size))
    }
}



struct HttpProxyRemote {
    connection: TcpStream,
    token: Token,
    tunnel_remote: Rc<RefCell<TunnelPacketBuffer>>,
    tunnel_client: Rc<RefCell<TunnelPacketBuffer>>,
}

impl HttpProxyRemote {
    fn from_existed_connection(
        token_id: usize,
        remote_cnt: TcpStream,
        tunnel_remote: Rc<RefCell<TunnelPacketBuffer>>,
        tunnel_client: Rc<RefCell<TunnelPacketBuffer>>,
    ) -> Self {
        Self {
            connection: remote_cnt,
            token: Token(token_id),
            tunnel_remote,
            tunnel_client,
        }
    }
}

impl EventHandler for HttpProxyRemote {
    fn target(&mut self) -> (&mut dyn Source, Token, Interest) {
        (&mut self.connection, self.token, Interest::WRITABLE | Interest::READABLE)
    }

    fn set_token_id(&mut self, tid: usize) {
        self.token = Token(tid);
    }

    fn handle(mut self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_writable() {
            match (self.tunnel_remote.borrow_mut()).write_into(&mut self.connection) {
                Ok(Some(n)) => {
                    if n == 0 {
                        // println!("HttpProxyRemote : write zero byte and end listening");
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
            match (self.tunnel_client.borrow_mut()).read_from(&mut self.connection) {
                Ok(Some(n)) => {
                    if n == 0 {
                        // println!("HttpProxyRemote : remote closed.");
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
    Established(Rc<RefCell<TunnelPacketBuffer>>, Rc<RefCell<TunnelPacketBuffer>>),
    Fail,
    Waiting,
}

struct HttpProxyClient {
    connection: TcpStream,
    token: Token,
    buffer_read: Vec<u8>,
    buffer_write: Vec<u8>,
    tunnel: TunnelStatus,
}

impl HttpProxyClient {
    pub fn from_existed_source(token_id: usize, connection: TcpStream) -> Self {
        HttpProxyClient {
            connection,
            token: Token(token_id),
            buffer_read: vec![0; 4096],
            buffer_write: Vec::new(),
            tunnel: TunnelStatus::Waiting,
        }
    }
}

impl EventHandler for HttpProxyClient {
    fn target(&mut self) -> (&mut dyn Source, Token, Interest) {
        (&mut self.connection, self.token, Interest::READABLE | Interest::WRITABLE)
    }

    fn set_token_id(&mut self, tid: usize) {
        self.token = Token(tid);
    }

    fn handle(mut self: Box<Self>, evt: &Event, event_loop: &mut EventLoop) {
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

                            let connect_result = std::net::TcpStream::connect(&request_headers[":path"]);
                            if connect_result.is_err() {
                                // let msg = "Fail to connect to remote host.";
                                // notify_client_failure(msg);
                                println!("Client : Establish tunnel {:?} : {:?}",
                                    &request_headers[":path"], connect_result);
                                return;
                            }
                            let connection = TcpStream::from_std(connect_result.unwrap());

                            // construct the tunnel
                            let remote_tunnel_buffer = Rc::new(RefCell::new(TunnelPacketBuffer::new()));
                            let client_tunnel_buffer = Rc::new(RefCell::new(TunnelPacketBuffer::new()));
                            self.tunnel = TunnelStatus::Established(
                                Rc::clone(&remote_tunnel_buffer),
                                Rc::clone(&client_tunnel_buffer),
                            );

                            let remote_token_id = self.token.0 | 1;
                            let remote = HttpProxyRemote::from_existed_connection(
                                remote_token_id,
                                connection,
                                Rc::clone(&remote_tunnel_buffer),
                                Rc::clone(&client_tunnel_buffer),
                            );
                            let register_result = event_loop.register(Box::new(remote));
                            if register_result.is_err() {
                                println!("Remote : register : Fail");
                                return;
                            }

                            client_tunnel_buffer.borrow_mut()
                                .push_bytes("HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes());
                        }
                        Err(e) => {
                            println!("Client : Read : {:?}", e);
                            return;
                        }
                    }
                }
                TunnelStatus::Established(ref remote_tunnel_buffer, _) => {
                    let connection = &mut self.connection;
                    match remote_tunnel_buffer.borrow_mut().read_from(connection) {
                        Ok(Some(n)) => {
                            if n == 0 {
                                // println!("Client : Tunnel : closing connection (by local).");
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
                _ => {}
            }
        }

        if evt.is_writable() {
            match self.tunnel {
                TunnelStatus::Waiting => {}
                TunnelStatus::Established(_, ref client_tunnel_buffer) => {
                    let mut buf_ref = client_tunnel_buffer.borrow_mut();
                    match buf_ref.write_into(&mut self.connection) {
                        Ok(Some(n)) => {
                            if n == 0 {
                                // println!("Client : Tunnel : closing connection");
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
                TunnelStatus::Fail => {
                    return;
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
}


impl EventHandler for HttpProxyServer {
    fn target(&mut self) -> (&mut dyn Source, Token, Interest) {
        (&mut self.listener, self.token, Interest::READABLE)
    }

    fn set_token_id(&mut self, tid: usize) {
        self.token = Token(tid);
    }

    fn handle(mut self: Box<Self>, _evt: &Event, event_loop: &mut EventLoop) {
        match self.listener.accept() {
            Ok((sock, _address)) => {
                let client_token_id = self.as_mut().counter.get();
                let client = HttpProxyClient::from_existed_source(client_token_id, sock);
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
    pub fn new(address: SocketAddr) -> io::Result<HttpProxyServer> {
        let listener = match TcpListener::bind(address) {
            Ok(listener) => listener,
            Err(e) => { return Err(e) },
        };
        Ok(HttpProxyServer {
            listener: listener,
            token: Token(17),
            counter: IncrementalCounter::new(),
        })
    }
}

