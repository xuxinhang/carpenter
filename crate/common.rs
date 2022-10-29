use std::io;
use std::fs;
use std::str::FromStr;


#[derive(Clone, Debug)]
pub struct HostAddr(pub Hostname, pub u16);

// TODO
#[derive(Clone, Debug)]
pub struct HostParseError;

impl FromStr for HostAddr {
    type Err = HostParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = s.rsplit_once(':').unwrap_or((s, "80"));
        Ok(Self(Hostname::from_str(x.0)?, x.1.parse().unwrap_or(80)))
    }
}

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

impl FromStr for Hostname {
    type Err = HostParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(v) = s.parse() {
            Ok(Hostname::Addr6(v))
        } else if let Ok(v) = s.parse() {
            Ok(Hostname::Addr4(v))
        } else {
            Ok(Hostname::Domain(s.to_string()))
            // TODO: check whether a valid domain name
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

