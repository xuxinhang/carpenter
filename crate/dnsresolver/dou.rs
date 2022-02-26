use std::io;
use std::rc::Rc;
use std::cell::RefCell;
use std::net::{SocketAddr};
use mio::{Token, Interest};
use mio::event::{Event};
use mio::net::{UdpSocket};
use crate::event_loop::{EventLoop, EventHandler, EventRegistryIntf};
use super::DnsResolveCallback;
use super::utils::{build_dns_query_message, parse_dns_response_message};


pub struct DnsDouResolver {
    dns_host: SocketAddr,
}

impl DnsDouResolver {
    pub fn new(host: SocketAddr) -> Self {
        Self { dns_host: host }
    }

    pub fn query(
        &self,
        name: &str,
        callback: Box<dyn DnsResolveCallback>,
        token: Token,
        event_loop: &mut EventLoop,
    ) -> () {
        let socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap());
        let socket = UdpSocket::bind("0.0.0.0:0".parse().unwrap());
        if let Err(e) = socket {
            println!("DnsDouResolver # tx_socket Error {:?}", e);
            return;
        }
        let socket = socket.unwrap();
        if let Err(e) = socket.connect(self.dns_host) {
            println!("DnsDouResolver # socket.connect {:?}", e);
            return;
        }

        let dns_msg = build_dns_query_message(name);
        if dns_msg.is_err() {
            println!("DnsDotResolver # Fail to build DNS message {:?}", dns_msg.unwrap_err());
            return;
        }
        let dns_msg = dns_msg.unwrap();

        let prof = DnsDouProfile {
            socket,
            token,
            sent_dns_message: dns_msg,
            // received_dns_messages: Vec
        };
        println!("E");
        event_loop.register(Box::new(DnsDouResolverSenderWritableHandler {
            profile: Rc::new(RefCell::new(prof)),
            callback: callback,
        })).unwrap();
    }
}


struct DnsDouProfile {
    socket: UdpSocket,
    token: Token,
    sent_dns_message: Vec<u8>,
    // received_dns_messages: Vec<u8>,
}


struct DnsDouResolverSenderWritableHandler {
    profile: Rc<RefCell<DnsDouProfile>>,
    callback: Box<dyn DnsResolveCallback>,
}

impl EventHandler for DnsDouResolverSenderWritableHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let prof = &mut *self.profile.borrow_mut();
        registry.register(&mut prof.socket, prof.token, Interest::WRITABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_writable() {
            println!("ERTT");
            let mut borw = self.profile.borrow_mut();
            let prof = &mut * borw;
            let size = prof.socket.send(&prof.sent_dns_message);
            if let Err(e) = size {
                println!("DnsDouResolverSenderWritableHandler # sender_socket.send {:?}", e);
                return;
            }

            drop(prof);
            drop(borw);

            event_loop.reregister(Box::new(DnsDouResolverReceiverReadableHandler {
                profile: self.profile.clone(),
                callback: self.callback,
            })).unwrap();
        }
    }
}


struct DnsDouResolverReceiverReadableHandler {
    profile: Rc<RefCell<DnsDouProfile>>,
    callback: Box<dyn DnsResolveCallback>,
}

impl EventHandler for DnsDouResolverReceiverReadableHandler {
    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let prof = &mut *self.profile.borrow_mut();
        registry.reregister(&mut prof.socket, prof.token, Interest::READABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_readable() {
            let prof = &mut * self.profile.borrow_mut();
            let mut buffer = vec![0; 65536];
            let size = prof.socket.recv(&mut buffer);
            if let Err(e) = size {
                println!("DnsDouResolverReceiverReadableHandler # recv {:?}", e);
                return;
            }
            buffer.resize(size.unwrap(), 0);

            let addr = match parse_dns_response_message(&buffer) {
                Ok(maybe_addr) => maybe_addr,
                Err(e) => {
                    println!("DnsDouResolver # parse_dns_response_message error {:?}", e);
                    None
                }
            };
            self.callback.dns_resolve_ready(addr, event_loop);
        }
    }
}


