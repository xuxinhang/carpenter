use std::io;
use std::io::{Read, Write};
// use std::collections::HashMap;
use mio::{Interest};
use mio::event::{Event, Source};
use mio::net::{TcpListener, TcpStream};
use std::net::{SocketAddr};
use crate::event_loop::{EventHandler, EventLoop};


struct HttpProxyClient {
    connection: TcpStream,
    buffer_read: Vec<u8>,
    buffer_write: Vec<u8>,
}

impl HttpProxyClient {
    pub fn from_existed_source(connection: TcpStream) -> Self {
        HttpProxyClient {
            connection,
            buffer_read: vec![0; 4096],
            buffer_write: Vec::new(),
        }
    }
}

impl EventHandler for HttpProxyClient {
    fn target(&mut self) -> (&mut dyn Source, Interest) {
        (&mut self.connection, Interest::READABLE | Interest::WRITABLE)
    }
    fn handle(&mut self, evt: &Event, _event_loop: &mut EventLoop) -> bool {
        let cnt = &mut self.connection;
        if evt.is_readable() {
            match cnt.read(&mut self.buffer_read) {
                Ok(0) => {
                    println!("Connection closed by client.");
                }
                Ok(n) => {
                    println!("Receive bytes from client: {}", n);
                    let mut resp_content = String::new();
                    resp_content.push_str("\
                        HTTP/1.1 200 OK\n\
                        content-type: application/json\n\
                        content-length: 15\n\n\
                        {\"hello\": null}
                    ");
                    self.buffer_write.append(&mut resp_content.as_bytes().to_owned());
                }
                Err(_) => {
                    println!("Fail to read.");
                }
            }
        }
        if evt.is_writable() {
            match cnt.write(&self.buffer_write) {
                Ok(n) => {
                    self.buffer_write.splice(..n, []);
                    // if cnt.shutdown(Shutdown::Both).is_err() {
                    return false;
                }
                Err(_) => {
                    println!("Fail to write.");
                }
            }
        }
        true
    }
}


pub struct HttpProxyServer {
    listener: TcpListener,
    // clients: HashMap<mio::Token, HttpProxyClient>,
}


impl EventHandler for HttpProxyServer {
    fn handle(&mut self, _evt: &Event, event_loop: &mut EventLoop) -> bool {
        match self.listener.accept() {
            Ok((sock, address)) => {
                let client = HttpProxyClient::from_existed_source(sock);
                match event_loop.register(client) {
                    Ok(_tok) => {
                        println!("Listening the incoming connection from {}", address);
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
        true
    }
    fn target(&mut self) -> (&mut dyn Source, Interest) {
        (&mut self.listener, Interest::READABLE)
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
            // clients: HashMap::new(),
        })
    }

    // pub fn inject_loop(self, el: &mut EventLoop) {
    //     el.register(&mut self.listener, Interest::READABLE, handler);
    // }
}

