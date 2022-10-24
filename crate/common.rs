use std::io;
use std::fs;


#[derive(Clone, Debug)]
pub enum Hostname {
    Addr4(std::net::Ipv4Addr),
    Addr6(std::net::Ipv6Addr),
    Domain(String),
}

impl ToString for Hostname {
    fn to_string(&self) -> String {
        match self {
            Hostname::Addr4(v) => v.to_string(),
            Hostname::Addr6(v) => v.to_string(),
            Hostname::Domain(v) => v.to_string(),
        }
    }
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

