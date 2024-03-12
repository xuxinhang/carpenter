// some common-used functions in every proxy server.

use std::net::{SocketAddr, IpAddr};
use crate::event_loop::EventLoop;
use crate::common::HostAddr;
use crate::proxy_client::{get_proxy_client, ProxyClientReadyCall, ProxyClient};
use crate::dnsresolver::{DnsQueier, DnsResolveCallback};


pub fn prepare_proxy_client_to_remote_host(
    host: HostAddr,
    event_loop: &mut EventLoop,
    callback: Box<dyn ProxyClientReadyCall>,
) {
    match get_proxy_client(&host) {
        Ok((client, is_dns_resolve_required)) => {
            if is_dns_resolve_required {
                let query_callback = Box::new(RemoteHostQueryDoneCallback {
                    remote_host: host.clone(),
                    proxy_client: client,
                    proxy_client_callback: callback,
                });
                let querier = DnsQueier::new(host.host());
                querier.query(query_callback, event_loop);
            } else {
                let token = event_loop.token.get();
                let x = client.connect(token, event_loop, host, callback);
                if let Err(e) = x {
                    wd_log::log_warn_ln!("ProxyQueryDoneHandler # ProxyClientDirect::connect error {:?}", e);
                    return;
                }
            }
        },
        Err(e) => {
            // Handle the error appropriately, e.g., log it, return it, etc.
            wd_log::log_error_ln!("Failed to get proxy client: {:?}", e);
            // Depending on the function's return type, you might return an error here
        }
    }
}
struct RemoteHostQueryDoneCallback {
    remote_host: HostAddr,
    proxy_client: Box<dyn ProxyClient>,
    proxy_client_callback: Box<dyn ProxyClientReadyCall>,
}

impl DnsResolveCallback for RemoteHostQueryDoneCallback {
    fn ready(self: Box<Self>, addr: Option<IpAddr>, event_loop: &mut EventLoop) {
        if addr.is_none() {
            wd_log::log_warn_ln!("ProxyQueryDoneHandler # Fail to resolve host {:?}", &self.remote_host);
            return;
        }

        let remote_ipaddr = addr.unwrap();
        let remote_port = self.remote_host.port();
        let remote_hostname = self.remote_host.host();
        wd_log::log_info_ln!("DNS Query result for \"{:?}\" is \"{:?}\"",
            remote_hostname, remote_ipaddr);

        let x = self.proxy_client.connect(
            event_loop.token.get(),
            event_loop,
            HostAddr::from(SocketAddr::from((remote_ipaddr, remote_port))),
            self.proxy_client_callback,
        );

        if x.is_err() {
            wd_log::log_warn_ln!("ProxyQueryDoneHandler # ProxyClientDirect::connect error");
            return;
        }
    }
}

