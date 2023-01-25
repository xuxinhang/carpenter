use std::net::{IpAddr};
use std::str::FromStr;
use crate::event_loop::{EventLoop};
use crate::configuration::{QuerierAction, DnsServerProtocol};
use crate::common::HostName;


mod utils;
mod cache;
mod dot;
mod dou;


pub use mio::Token;
pub use dot::DnsDotResolver;
pub use dou::DnsDouResolver;
pub use cache::DnsCacheHolder;



pub trait DnsResolveCallback {
    fn dns_resolve_ready(self: Box<Self>, ip: Option<IpAddr>, event_loop: &mut EventLoop) {
        self.ready(ip, event_loop);
    }
    fn ready(self: Box<Self>, ip: Option<IpAddr>, event_loop: &mut EventLoop);
}

pub trait DnsResolver {
    fn query(
        &self,
        name: &str,
        callback: Box<dyn DnsResolveCallback>,
        token: Token,
        event_loop: &mut EventLoop,
    ) -> ();
}



pub struct DnsQueier {
    hostname: HostName,
}

impl DnsQueier {
    pub fn new(hostname: HostName) -> Self {
        Self { hostname }
    }

    pub fn query_cache(&self, hostname: &str) -> Option<IpAddr> {
       let x = crate::global::get_global_stuff().borrow().dns_cache.get(hostname);
       return x;
    }

    pub fn query(
        &self,
        query_ready_callback: Box<dyn DnsResolveCallback>,
        event_loop: &mut EventLoop,
    ) -> Option<IpAddr> {
        let global_config = crate::global::get_global_config();

        // Return itself directly if IpAddr
        match self.hostname {
            HostName::IpAddress(v) => {
                let ipaddr = v;
                query_ready_callback.ready(Some(ipaddr), event_loop);
                return Some(ipaddr);
            }
            HostName::DomainName(_) => {}
        }

        // Lookup the cache first
        if let Some(x) = self.query_cache(&self.hostname.to_string()) {
            query_ready_callback.ready(Some(x), event_loop);
            return Some(x);
        }

        // Send query request to dns server
        let domain_name = self.hostname.to_string();
        let hostname = domain_name.as_str();

        let mut target_hostname = String::from(hostname);
        let mut target_loopdeepth = 0;
        while target_loopdeepth < 100 {
            if let Ok(ipaddr) = IpAddr::from_str(&target_hostname) {
                wd_log::log_info_ln!("Querier (IP) {}", ipaddr);
                query_ready_callback.ready(Some(ipaddr), event_loop);
                return Some(ipaddr);
            }

            target_loopdeepth += 1;

            match global_config.get_querier_action_by_domain_name(&target_hostname) {
                Some(QuerierAction::To(t)) => {
                    wd_log::log_info_ln!("Querier (re-target) to {}", t);
                    target_hostname = t.to_string();
                    continue;
                }
                Some(QuerierAction::Dns(d)) => {
                    let x = crate::global::get_global_config().core.dns_server.get(&d);
                    if x.is_none() {
                        wd_log::log_info_ln!("ProxyRequestHandler # dns server not found.");
                        return None;
                    }

                    let (dns_protocol, dns_addr) = x.unwrap();
                    let dns_client: Box<dyn DnsResolver> = match dns_protocol {
                        DnsServerProtocol::Tls => {
                            wd_log::log_info_ln!("Querier (DoT) {}", target_hostname);
                            Box::new(DnsDotResolver::new(*dns_addr))
                        }
                        DnsServerProtocol::Udp => {
                            wd_log::log_info_ln!("Querier (DoU) {}", target_hostname);
                            Box::new(DnsDouResolver::new(*dns_addr))
                        }
                    };
                    let tk = event_loop.token.get();
                    dns_client.query(&target_hostname, query_ready_callback, tk, event_loop);
                    return None;
                }
                None => {
                    wd_log::log_warn_ln!("ProxyRequestHandler # cannot find a querier action.");
                    return None;
                }
            }
        }

        return None;
    }
}

