use std::io;
use std::fs;
use std::str::FromStr;
use std::net::{SocketAddr, IpAddr};
use std::convert::{TryInto, From};


#[derive(Clone, Debug, PartialEq)]
pub struct HostAddr(pub HostName, pub u16);

impl HostAddr {
    pub fn host(&self) -> HostName {
        self.0.clone()
    }
    pub fn port(&self) -> u16 {
        self.1
    }
}

#[derive(Clone, Debug)]
pub struct HostParseError();

impl TryInto<SocketAddr> for HostAddr {
    type Error = ();
    fn try_into(self) -> Result<SocketAddr, Self::Error> {
        if let HostName::IpAddress(h) = self.host() {
            Ok((h, self.port()).into())
        } else {
            Err(())
        }
    }
}

impl From<SocketAddr> for HostAddr {
    fn from(s: SocketAddr) -> Self {
        HostAddr(HostName::IpAddress(s.ip()), s.port())
    }
}

impl FromStr for HostAddr {
    type Err = HostParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let first_char = s.chars().next();
        let (h, i) = match first_char {
            Some('[') => {
                let i = s.find(']').ok_or(HostParseError())?;
                let ip = s[1..i].parse().map_err(|_| HostParseError())?;
                (HostName::IpAddress(ip), i+1)
            }
            Some(x) if x.is_digit(10) => {
                let i = s.find(':').unwrap_or(s.len());
                let ip = s[0..i].parse().map_err(|_| HostParseError())?;
                (HostName::IpAddress(ip), i)
            }
            _ => {
                let i = s.find(':').unwrap_or(s.len());
                (HostName::DomainName(s[0..i].to_string()), i)
            }
        };
        let p = match s.chars().nth(i) {
            Some(':') => s[i+1..].parse().map_err(|_| HostParseError())?,
            None => 80,
            _ => return Err(HostParseError()),
        };

        Ok(Self(h, p))
    }
}

impl ToString for HostAddr {
    fn to_string(&self) -> String {
        let use_bracket = self.host().as_ip_address().map_or(false, |x| x.is_ipv6());
        let mut cont = self.host().to_string();
        if use_bracket {
            cont.insert(0, '[');
            cont.push(']');
        }
        cont.push(':');
        cont.push_str(self.port().to_string().as_str());
        return cont;
    }
}


#[derive(Clone, Debug, PartialEq)]
pub enum HostName {
    IpAddress(std::net::IpAddr),
    DomainName(String),
}

impl HostName {
    fn _is_domain_name(&self) -> bool {
        match self {
            Self::IpAddress(_) => true,
            Self::DomainName(_) => false,
        }
    }
    fn _is_ip_address(&self) -> bool {
        match self {
            Self::IpAddress(_) => false,
            Self::DomainName(_) => true,
        }
    }
    fn as_ip_address(&self) -> Option<&IpAddr> {
        match self {
            Self::IpAddress(ref x) => Some(x),
            Self::DomainName(_) => None,
        }
    }
    fn _as_domain_name(&self) -> Option<&str> {
        match self {
            Self::IpAddress(_) => None,
            Self::DomainName(ref x) => Some(x),
        }
    }
}

impl ToString for HostName {
    fn to_string(&self) -> String {
        match self {
            Self::IpAddress(x) => x.to_string(),
            Self::DomainName(x) => x.to_string(),
        }
    }
}

impl FromStr for HostName {
    type Err = HostParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(x) = s.parse() {
            Ok(Self::IpAddress(x))
        } else {
            // TODO: check whether a valid domain name
            Ok(Self::DomainName(s.to_string()))
        }
    }
}


pub fn load_tls_certificate(file_path: &str) -> io::Result<Vec<rustls::Certificate>> {
    let certname = file_path;
    let certfile = fs::File::open(certname)?;
    let certdata = rustls_pemfile::certs(&mut io::BufReader::new(certfile))
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();
    Ok(certdata)
}


pub fn load_tls_private_key(file_path: &str) -> io::Result<rustls::PrivateKey> {
    let pkeyname = file_path;
    let pkeyfile = fs::File::open(pkeyname)?;
    let mut pkeyreader = io::BufReader::new(pkeyfile);
    let pkeydata = loop {
        match rustls_pemfile::read_one(&mut pkeyreader)
            .expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => break rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => break rustls::PrivateKey(key),
            None => panic!("no keys found in {:?} (encrypted keys not supported)", pkeyname),
            _ => {}
        }
    };
    Ok(pkeydata)
}

