use std::net::{IpAddr};
use crate::event_loop::{EventLoop};


mod utils;
mod dot;
mod dou;


pub use dot::DnsDotResolver;
pub use dou::DnsDouResolver;


pub trait DnsResolveCallback {
    fn dns_resolve_ready(self: Box<Self>, ip: Option<IpAddr>, event_loop: &mut EventLoop);
}

