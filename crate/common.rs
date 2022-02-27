// use std::net::ToSocketAddrs;

#[derive(Clone, Debug)]
pub enum Hostname {
    Addr4(std::net::Ipv4Addr),
    Addr6(std::net::Ipv6Addr),
    Domain(String),
}

#[derive(Debug)]
pub struct HostnameParseError();

impl std::str::FromStr for Hostname {
    type Err = HostnameParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ip_addr) = s.parse() {
            return Ok(Hostname::Addr4(ip_addr));
        } else if let Ok(ip_addr) = s.parse() {
            return Ok(Hostname::Addr6(ip_addr));
        } else if let Ok(domain) = s.parse() {
            return Ok(Hostname::Domain(domain));
        } else {
            return Err(HostnameParseError());
        }
    }
}

pub trait ToHostname {
    fn to_hostname(&self) -> Result<Hostname, HostnameParseError>;
}

impl ToHostname for str {
    fn to_hostname(&self) -> Result<Hostname, HostnameParseError> {
        self.parse()
    }
}

// impl ToHostname for Hostname {
//     fn to_hostname(&self) -> Result<Hostname, HostnameParseError> {
//         Ok(*self)
//     }
// }
