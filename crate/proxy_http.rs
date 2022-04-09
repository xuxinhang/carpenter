use std::str::FromStr;
use std::io;
use std::io::{Read, Write};
use std::rc::Rc;
use std::cell::RefCell;
use mio::{Interest, Token};
use mio::event::{Event};
use mio::net::{TcpListener, TcpStream};
use std::net::{SocketAddr, Shutdown, ToSocketAddrs, IpAddr};
use crate::event_loop::{EventHandler, EventLoop, EventRegistryIntf};
use crate::http_header_parser::parse_http_header;
use crate::transformer::{TransferResult, TunnelTransformer, TunnelSniomitTransformer, TunnelDirectTransformer};
use crate::proxy_client::{ProxyClientReadyCall, direct::ProxyClientDirect};
use crate::configuration::{TransformerAction, QuerierAction, DnsServerProtocol};
use crate::dnsresolver::{DnsResolveCallback, DnsDotResolver, DnsDouResolver};



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


fn store_dns_record_into_global_dns_cache(domain: &str, ip: IpAddr) {
   crate::global::get_global_stuff().borrow_mut().dns_cache.store(domain, ip);
}

fn fetch_dns_record_from_global_dns_cache(domain: &str) -> Option<IpAddr> {
   crate::global::get_global_stuff().borrow().dns_cache.get(domain)
}


pub struct HttpProxyServer {
    listener: TcpListener,
    token: Token,
    counter: IncrementalCounter,
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
            token: Token(17),
            counter: IncrementalCounter::new(),
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
                    client: ClientShakingConnection::from_connection(Token(token_id + 1), conn),
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
    token: Token,
    client_conn: TcpStream,
}

impl ClientShakingConnection {
    fn from_connection(token: Token, conn: TcpStream) -> Self {
        Self { client_conn: conn, token }
    }
}

struct ClientShakingAgreement {
    token: Token,
    client_conn: TcpStream,
    is_http_tunnel_mode: bool,
}


struct Tunnel {
    is_http_tunnel_mode: bool,
    local_token: Token,
    local_conn: TcpStream,
    remote_token: Token,
    remote_conn: TcpStream,
    transformer: Box<dyn TunnelTransformer>,
}

impl Tunnel {
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
    client: ClientShakingConnection,
}

impl EventHandler for ProxyRequestHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.client.client_conn, self.client.token, Interest::READABLE)
    }

    fn handle(mut self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        let global_config = crate::global::get_global_config();

        if event.is_readable() {
            let conn = &mut self.client.client_conn;

            let mut msg_buf = vec![0u8; 4*1024*1024];
            if let Err(e) = conn.peek(&mut msg_buf) {
                wd_log::log_error_ln!("ProxyRequestHandler # peek error. {:?}", e);
                return;
            }

            let result = parse_http_header(&msg_buf);
            if result.is_none() {
                wd_log::log_warn_ln!("ProxyRequestHandler # Invalid HTTP message.");
                return;
            }
            let (header_length, msg_header_map, _msg_header_vec) = result.unwrap();

            let (
                is_http_tunnel_mode,
                remote_hostname,
                remote_port,
                // early_data,
            ) = if msg_header_map[":method"].as_str() == "CONNECT" {
                let request_host = &msg_header_map[":path"];
                let result = request_host.rsplit_once(':')
                    .and_then(|x| Some(x.0).zip(x.1.parse().ok()));
                if result.is_none() {
                    wd_log::log_warn_ln!("ProxyRequestHandler # invalid request host: {}", request_host);
                    return;
                }
                let (hostname, port) = result.unwrap();

                // we don't need this header any more
                let mut trash = vec![0; header_length];
                if conn.read(&mut trash).is_err() {
                    wd_log::log_error_ln!("ProxyRequestHandler # read error.");
                    return;
                }

                (true, hostname, port)
            } else {
                // get hostname and port
                let request_path = &msg_header_map[":path"];
                let result = request_path.split_once("://");
                if result.is_none() {
                    wd_log::log_warn_ln!("unexpected request path: {}", request_path);
                    return;
                }
                let (_protocal_str, authority_and_origin_str) = result.unwrap();


                let (authority_str, _origin_str) = authority_and_origin_str.find('/')
                    .map(|i| authority_and_origin_str.split_at(i))
                    .unwrap_or((authority_and_origin_str, "/"));
                let (hostname, port) = match authority_str.rsplit_once(':') {
                    None => (authority_str, 80),
                    Some((h, p)) => (h, u16::from_str(p).unwrap()),
                };

                /*/ rebuilt HTTP/1.1 message (TODO: follow RFC 7230)
                let mut rebuilt_message = Vec::<u8>::new();
                rebuilt_message.write(format!(
                    "{} {} {}\r\n",
                    msg_header_map[":method"],
                    if msg_header_map[":method"] == "OPTION" { "*" } else { origin_str },
                    msg_header_map[":version"],
                ).as_bytes()).unwrap();
                for hkey in msg_header_vec.iter() {
                    let hval = msg_header_map.get(hkey).unwrap();
                    let hkey_used = match hkey.as_str() {
                        // "Proxy-Connection" => "Connection",
                        // "Connection" => "",
                        s => s,
                    };
                    if !hkey_used.is_empty() {
                        rebuilt_message.write(
                            format!("{}: {}\r\n", hkey_used, hval).as_bytes()).unwrap();
                    }
                }
                rebuilt_message.write("\r\n".as_bytes()).unwrap();
                rebuilt_message.write(&msg_buf[header_length..]).unwrap(); */

                (false, hostname, port)
            };

            // 1) DNS resolve
            let query_ready_callback = Box::new(ProxyQueryDoneCallback {
                client: ClientShakingAgreement {
                    token: self.client.token,
                    client_conn: self.client.client_conn,
                    is_http_tunnel_mode,
                },
                remote_hostname: remote_hostname.to_string(),
                remote_port: remote_port,
            });
            if let Some(addr) = fetch_dns_record_from_global_dns_cache(remote_hostname) {
                wd_log::log_info_ln!("Querier (cached result) {}", remote_hostname);
                query_ready_callback.do_work(Some(addr), event_loop);
            } else {
                let mut target_hostname = remote_hostname.to_string();
                let mut target_step_count = 0;
                loop {
                    match global_config.querier_matcher.get(&target_hostname) {
                        Some(QuerierAction::To(t)) => {
                            wd_log::log_info_ln!("Querier (re-target) to {}", t);
                            target_hostname = t.to_string();
                            if target_step_count > 100 {
                                wd_log::log_warn_ln!("ProxyRequestHandler # too many re-targetting");
                                return;
                            }
                            target_step_count += 1;
                            continue;
                        }
                        Some(QuerierAction::Dns(d)) => {
                            if let Ok(ip_addr) = IpAddr::from_str(&target_hostname) {
                                // use IP address direcly if given
                                wd_log::log_info_ln!("Querier (IP) {}", ip_addr);
                                query_ready_callback.do_work(Some(ip_addr), event_loop);
                            } else {
                                let dns_query_token = Token(query_ready_callback.client.token.0 + 7);
                                match crate::global::get_global_config().core.dns_server.get(&d) {
                                    None => {
                                        wd_log::log_info_ln!("ProxyRequestHandler # cannot find the assigned querier server.");
                                        return;
                                    }
                                    Some((dns_server_protocol, dns_server_addr)) => {
                                        match dns_server_protocol {
                                            DnsServerProtocol::Tls => {
                                                wd_log::log_info_ln!("Querier (DoT) {}", target_hostname);
                                                let resolver = DnsDotResolver::new(*dns_server_addr);
                                                resolver.query(&target_hostname, query_ready_callback, dns_query_token, event_loop);
                                            }
                                            DnsServerProtocol::Udp => {
                                                wd_log::log_info_ln!("Querier (DoU) {}", target_hostname);
                                                let resolver = DnsDouResolver::new(*dns_server_addr);
                                                resolver.query(&target_hostname, query_ready_callback, dns_query_token, event_loop);
                                            }
                                        }
                                    }
                                }
                            }
                            break;
                        }
                        None => {
                            wd_log::log_warn_ln!("ProxyRequestHandler # cannot find a querier action.");
                            return;
                        }
                    }
                }
            }
        }
    }
}


struct ProxyQueryDoneCallback {
    client: ClientShakingAgreement,
    remote_hostname: String,
    remote_port: u16,
}

impl DnsResolveCallback for ProxyQueryDoneCallback {
    fn dns_resolve_ready(self: Box<Self>, addr: Option<IpAddr>, event_loop: &mut EventLoop) {
        if addr.is_none() {
            println!("ProxyQueryDoneHandler # Fail to resolve host \"{}\"", self.remote_hostname);
            return;
        }
        let addr = addr.unwrap();
        wd_log::log_info_ln!("DNS Query result for \"{}\" is \"{}\"", self.remote_hostname, addr);
        store_dns_record_into_global_dns_cache(&self.remote_hostname, addr.clone());
        self.do_work(Some(addr), event_loop);
    }
}

impl ProxyQueryDoneCallback {
    fn do_work(self: Box<Self>, addr: Option<IpAddr>, event_loop: &mut EventLoop) {
        let global_config = crate::global::get_global_config();

        if addr.is_none() {
            println!("ProxyQueryDoneHandler # Fail to resolve host \"{}\"", self.remote_hostname);
            return;
        }
        let addr = addr.unwrap();

        // 1) Decide which transformer to use
        let request_hostname = self.remote_hostname.as_str();
        let request_port = self.remote_port;
        let transformer_config =
            global_config.transformer_matcher.get(request_port, request_hostname);
        let transformer_boxed: Box<dyn TunnelTransformer> = match transformer_config {
            Some(TransformerAction::SniTransformer(s)) => {
                let (sni_enable, sni_value) = match s.as_str() {
                    "_" => (false, request_hostname),
                    "*" => (true, request_hostname),
                    h => (true, h),
                };
                wd_log::log_info_ln!("Use transformer: SNI Rewritter \"{}\"",
                    if sni_enable { sni_value } else { "<omitted>" });
                let transformer = TunnelSniomitTransformer::new(
                    request_hostname,
                    sni_value,
                    sni_enable,
                );
                if let Err(e) = transformer {
                    println!("ProxyQueryDoneCallback # TunnelSniomitTransformer::new {:?}", e);
                    return;
                }
                Box::new(transformer.unwrap())
            }
            Some(TransformerAction::DirectTransformer) | None => {
                wd_log::log_info_ln!("Use transformer: Direct");
                Box::new(TunnelDirectTransformer::new())
            }
        };

        // 2) Establish outbound data tunnel.
        let mut socket_addr = (addr, self.remote_port).to_socket_addrs().unwrap();
        let mut proxy_client = ProxyClientDirect::new(socket_addr.next().unwrap());
        let result = proxy_client.connect(
            Token(self.client.token.0 + 1),
            event_loop,
            Box::new(ProxyRequestConnectedHandler {
                client: self.client,
                transformer: transformer_boxed, // Box::new(transformer),
            }),
        );
        if result.is_err() {
            wd_log::log_warn_ln!("ProxyQueryDoneHandler # ProxyClientDirect::connect error");
            return;
        }
    }
}


struct ProxyRequestConnectedHandler {
    client: ClientShakingAgreement,
    transformer: Box<dyn TunnelTransformer>,
}

impl ProxyClientReadyCall for ProxyRequestConnectedHandler {
    fn proxy_client_ready(self: Box<Self>, event_loop: &mut EventLoop, peer_source: TcpStream) -> io::Result<()> {
        let next_handler = ProxyResponseHandler {
            tunnel: Tunnel {
                is_http_tunnel_mode: self.client.is_http_tunnel_mode,
                local_token: Token(self.client.token.0 + 0),
                local_conn: self.client.client_conn,
                remote_token: Token(self.client.token.0 + 1),
                remote_conn: peer_source,
                transformer: self.transformer,
            }
        };
        event_loop.reregister(Box::new(next_handler)).unwrap();
        Ok(())
    }
}


struct ProxyResponseHandler {
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
            // Only HTTP Tunnel needs response with 200
            if self.tunnel.is_http_tunnel_mode {
                let message = "HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes();
                let conn = &mut self.tunnel.local_conn;
                if let Err(e) = conn.write(message) {
                    wd_log::log_warn_ln!("ProxyResponseHandler # fail to write {:?}", e);
                    return;
                }
            }

            // Both HTTP tunnel and HTTP forward-proxy need to register W/R handlers.
            let tunnel_ptr = Rc::new(RefCell::new(self.tunnel));
            event_loop.reregister(Box::new(ProxyTransferLocalReadableHandler {
                tunnel: tunnel_ptr.clone(),
            })).unwrap();
            event_loop.reregister(Box::new(ProxyTransferRemoteReadableHandler {
                tunnel: tunnel_ptr.clone(),
            })).unwrap();
            event_loop.reregister(Box::new(ProxyTransferLocalWritableHandler {
                tunnel: tunnel_ptr.clone(),
            })).unwrap();
            event_loop.reregister(Box::new(ProxyTransferRemoteWritableHandler {
                tunnel: tunnel_ptr.clone(),
            })).unwrap();
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
            event_loop.reregister(Box::new(ProxyTransferRemoteWritableHandler {
                tunnel: Rc::clone(&self.tunnel),
            })).unwrap();
        }
        if reregister_local_writable_flag {
            event_loop.reregister(Box::new(ProxyTransferLocalWritableHandler {
                tunnel: Rc::clone(&self.tunnel),
            })).unwrap();
        }
        if reregister_local_readable_flag {
            event_loop.reregister(self).unwrap();
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
            event_loop.reregister(Box::new(ProxyTransferLocalWritableHandler {
                tunnel: Rc::clone(&self.tunnel),
            })).unwrap()
        }
        if reregister_remote_writable_flag {
            event_loop.reregister(Box::new(ProxyTransferRemoteWritableHandler {
                tunnel: Rc::clone(&self.tunnel),
            })).unwrap();
        }
        if reregister_remote_readable_flag {
            event_loop.reregister(self).unwrap();
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
            event_loop.reregister(self).unwrap();
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
            event_loop.reregister(self).unwrap();
        }
    }
}
