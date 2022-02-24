use std::net::{IpAddr};
use crate::event_loop::{EventLoop};


mod dot;
mod utils;


pub use dot::DnsDotResolver;


pub trait DnsResolveCallback {
    fn dns_resolve_ready(self: Box<Self>, ip: Option<IpAddr>, event_loop: &mut EventLoop);
}

