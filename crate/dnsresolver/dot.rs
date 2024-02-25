use std::sync::Arc;
use std::rc::Rc;
use std::cell::RefCell;
use std::io;
use std::io::{Write, Read};
use std::net::{SocketAddr};
use mio::net::TcpStream;
use mio::{Token, Interest};
use mio::event::{Event};
use crate::event_loop::{EventLoop, EventHandler, EventRegistryIntf};
use rustls::{ClientConnection, ClientConfig};
use super::{DnsResolver, DnsResolveCallback};
use super::utils::{build_dns_query_message, parse_dns_response_message};


struct NoCertVerifier {}

impl rustls::client::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::client::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}


pub struct DnsDotResolver {
    dns_host: SocketAddr,
}

impl DnsDotResolver {
    pub fn new(host: SocketAddr) -> Self {
        Self { dns_host: host }
    }
}

impl DnsResolver for DnsDotResolver {
    fn query(
        &self,
        name: &str,
        callback: Box<dyn DnsResolveCallback>,
        token: Token,
        event_loop: &mut EventLoop,
    ) -> () {
        let mut remote_tls_conf =
            ClientConfig::builder()
                .with_safe_defaults()
                // @HACK: don't check the certificate subject alt name due to
                //        the lack of ability to check a IP address as a subject alt name
                .with_custom_certificate_verifier(Arc::new(NoCertVerifier {}))
                .with_no_client_auth();
        remote_tls_conf.enable_sni = false;
        let tls = ClientConnection::new(
            Arc::new(remote_tls_conf),
            "cloudflare-dns.com".try_into().unwrap(),
        );
        if let Err(e) = tls {
            wd_log::log_error_ln!("DnsDotResolver # fail to create TLS session {:?}", e);
            return;
        }
        let tls = tls.unwrap();

        let conn = TcpStream::connect(self.dns_host);
        if conn.is_err() {
            wd_log::log_error_ln!("DnsDotResolver # Error connect {:?}", conn.unwrap_err());
            return;
        }
        let conn = conn.unwrap();

        let mut profile = DnsDotResolverProfile {
            conn: conn,
            tls: tls,
            token: token,
            pending_dns_messages: Vec::new(),
            received_dns_messages: Vec::new(),
        };

        let dns_msg = build_dns_query_message(name);
        if dns_msg.is_err() {
            wd_log::log_error_ln!("DnsDotResolver # Fail to build DNS message {:?}", dns_msg.unwrap_err());
            return;
        }
        let mut dns_msg = dns_msg.unwrap();
        let msg_len = dns_msg.len() as u16;
        dns_msg.insert(0, (msg_len & 0xff) as u8); // Extra bytes via DNS over TCP
        dns_msg.insert(0, (msg_len >> 8) as u8);

        profile.pending_dns_messages.push(dns_msg);

        let profile_ptr = Rc::new(RefCell::new(profile));
        // let handler = DnsDotResolveRemoteReadableHandler {
        //     profile: profile_ptr.clone(),
        //     callback: callback,
        // };
        // event_loop.register(Box::new(handler)).unwrap();
        let handler = DnsDotResolveRemoteWritableHandler {
            profile: profile_ptr.clone(),
            callback: callback,
        };
        event_loop.register(Box::new(handler)).unwrap();
    }
}

struct DnsDotResolverProfile {
    conn: TcpStream,
    tls: ClientConnection,
    token: Token,
    pending_dns_messages: Vec<Vec<u8>>,
    received_dns_messages: Vec<Vec<u8>>,
}

struct DnsDotResolveRemoteWritableHandler {
    profile: Rc<RefCell<DnsDotResolverProfile>>,
    callback: Box<dyn DnsResolveCallback>,
}

impl EventHandler for DnsDotResolveRemoteWritableHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let prof = &mut *self.profile.borrow_mut();
        registry.register(&mut prof.conn, prof.token, Interest::WRITABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let prof = &mut *self.profile.borrow_mut();
        registry.reregister(&mut prof.conn, prof.token, Interest::WRITABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_writable() {
            let prof = &mut *self.profile.borrow_mut();

            if prof.tls.wants_write() {
                let write_size = prof.tls.write_tls(&mut prof.conn);
                if let Err(e) = write_size {
                    println!("DnsDotResolver # profile.tls.write_tls error {:?}", e);
                    return;
                }
            }
        }

        let handler = DnsDotResolveRemoteReadableHandler {
            profile: self.profile.clone(),
            callback: self.callback,
        };
        event_loop.reregister(Box::new(handler)).unwrap();
    }
}

struct DnsDotResolveRemoteReadableHandler {
    profile: Rc<RefCell<DnsDotResolverProfile>>,
    callback: Box<dyn DnsResolveCallback>,
}

impl EventHandler for DnsDotResolveRemoteReadableHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let prof = &mut *self.profile.borrow_mut();
        registry.register(&mut prof.conn, prof.token, Interest::READABLE)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let prof = &mut *self.profile.borrow_mut();
        registry.reregister(&mut prof.conn, prof.token, Interest::READABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_readable() {
            let prof = &mut *self.profile.borrow_mut();
            if prof.tls.wants_read() {
                let tls_read_size = prof.tls.read_tls(&mut prof.conn);
                if tls_read_size.is_err() {
                    println!("DnsDotResolver # prof.tls.read_tls Error {:?}", tls_read_size.unwrap_err());
                    return;
                }
                let tls_read_size = tls_read_size.unwrap();
                // println!("prof.tls.read_tls size {}", tls_read_size);
                if tls_read_size == 0 {
                    // println!("Close");
                    return;
                }

                let tls_state = prof.tls.process_new_packets();
                if let Err(e) = tls_state {
                    println!("DnsDotResolver # process_new_packets Error {:?}", e);
                    return;
                }
                let tls_state = tls_state.unwrap();

                if tls_state.plaintext_bytes_to_read() > 0 {
                    let mut buffer = vec![0; 1*1024*1024];
                    let plaintext_read_size = prof.tls.reader().read(&mut buffer);
                    if let Err(e) = plaintext_read_size {
                        println!("DnsDotResolver # Error read {:?}", e);
                        return;
                    }
                    let plaintext_read_size = plaintext_read_size.unwrap();
                    // println!("plaintext_read_size {}", plaintext_read_size);
                    // println!("DNS expected length {}", buffer[1]);
                    // println!("DNS message length {}", plaintext_read_size - 2);

                    let tail_size = {
                        let t = vec![0; 2];
                        let x = prof.received_dns_messages.last().unwrap_or(&t);
                        (((x[0] as usize) << 8) + x[1] as usize) - (x.len() - 2)
                    };
                    if tail_size > 0 {
                        prof.received_dns_messages.last_mut().unwrap()
                            .extend_from_slice(&buffer[..plaintext_read_size]);
                    }
                    if tail_size < plaintext_read_size {
                        prof.received_dns_messages
                            .push(buffer[tail_size..plaintext_read_size].to_vec());
                    }

                    let response_bytes = prof.received_dns_messages.last();
                    if response_bytes.is_none() {
                        println!("DnsDotResolver # no response data");
                        return;
                    }
                    let response_msg = &response_bytes.unwrap()[2..];
                    match parse_dns_response_message(response_msg) {
                        Ok(maybe_addr) => {
                            self.callback.dns_resolve_ready(maybe_addr, event_loop);
                            return;
                        }
                        Err(e) => {
                            println!("DnsDotResolver # parse_dns_response_message error {:?}", e);
                            self.callback.dns_resolve_ready(None, event_loop);
                            return;
                        }
                    }

                }

                if !prof.tls.is_handshaking() {
                    if !prof.pending_dns_messages.is_empty() {
                        let msg_dat = prof.pending_dns_messages.remove(0);
                        let msg_len = msg_dat.len();
                        match prof.tls.writer().write(&msg_dat) {
                            Ok(write_size) => {
                                if write_size < msg_len {
                                    prof.pending_dns_messages.insert(0, msg_dat[write_size..].to_vec());
                                }
                            }
                            Err(e) => {
                                println!("DnsDotResolver # profile.tls.write_all error {:?}", e);
                                return;
                            }
                        }
                    }
                }
            }
        }

        let handler = DnsDotResolveRemoteWritableHandler {
            profile: self.profile.clone(),
            callback: self.callback,
        };
        event_loop.reregister(Box::new(handler)).unwrap();
    }
}
