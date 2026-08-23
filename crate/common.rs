use std::io;
use std::fs;
use std::str::FromStr;
use std::net::{SocketAddr, IpAddr};
use std::convert::From;
use std::io::Read;
use domain::base::Dname;
use crate::certmgr::certstorage::{pem_to_der, ROOT_CA_CERTIFICATE_PATH};

#[derive(Clone, Debug)]
pub struct HostParseError();


#[derive(Clone, Debug)]
pub struct HostAddress(pub Hostname, pub u16);

impl From<SocketAddr> for HostAddress {
    fn from(socket: SocketAddr) -> Self {
        Self(Hostname::IpAddress(socket.ip()), socket.port())
    }
}

impl FromStr for HostAddress {
    type Err = HostParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ns, ps) = s.rsplit_once(':').ok_or(HostParseError())?;
        let nn = Hostname::from_str(ns)?;
        let pp: u16 = ps.parse().map_err(|_| HostParseError())?;
        Ok(Self(nn, pp))
    }
}

#[derive(Clone, Debug)]
pub enum Hostname {
    IpAddress(IpAddr),
    DnsName(Dname<Vec<u8>>),
}

impl ToString for Hostname {
    fn to_string(&self) -> String {
        match self {
            Self::IpAddress(x) => x.to_string(),
            Self::DnsName(x) => x.to_string(),
        }
    }
}

impl FromStr for Hostname {
    type Err = HostParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(x) = s.parse() {
            return Ok(Self::IpAddress(x));
        }
        if let Ok(x) = Dname::from_str(s) {
            return Ok(Self::DnsName(x));
        }
        Err(HostParseError())
    }
}


pub fn load_tls_certificate(file_path: &str) -> io::Result<Vec<rustls::Certificate>> {
    if file_path == ROOT_CA_CERTIFICATE_PATH {
        println!("file_path == ROOT_CA_CERTIFICATE_PATH");
        let certname = "_certificates/root_ca/certificate.der.crt";
        let certfile = fs::File::open(certname)?;
        let mut file_buffer = io::BufReader::new(certfile);
        let mut buffer= Vec::new();
        file_buffer.read_to_end(&mut buffer)?;
        return Ok(vec![rustls::Certificate(buffer)]);
    } else {
        let certfile = fs::File::open(file_path)?;
        let mut file_buffer = io::BufReader::new(certfile);
        let mut buffer= Vec::new();
        file_buffer.read_to_end(&mut buffer)?;
        let derb = pem_to_der(String::from_utf8_lossy(&buffer).into_owned().as_str());
        return Ok(vec![rustls::Certificate(derb)]);
    }

    // let certname = file_path;
    // let certfile = fs::File::open(certname)?;
    // let certdata = rustls_pemfile::certs(&mut io::BufReader::new(certfile))?
    //     .iter()
    //     .map(|v| rustls::Certificate(v.clone()))
    //     .collect();
    // Ok(certdata)
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

