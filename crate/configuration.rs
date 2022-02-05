use std::fs;
use std::io;
use std::io::BufReader;

pub struct GlobalConfiguration {
    pub tls_cert: Vec<rustls::Certificate>,
    pub tls_pkey: rustls::PrivateKey,
    pub openssl_path: String,
}

pub fn load_default_configuration() -> GlobalConfiguration {
    let certname = "./certs/default_crt.crt";
    let certfile = fs::File::open(certname).expect("cannot open certificate file");
    let certdata = rustls_pemfile::certs(&mut BufReader::new(certfile))
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();

    let pkeyname = "./certs/default_key.pem";
    let pkeyfile = fs::File::open(pkeyname).expect("cannot open private key file");
    let mut pkeyreader = BufReader::new(pkeyfile);
    let pkeydata = loop {
        match rustls_pemfile::read_one(&mut pkeyreader)
            .expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => break rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => break rustls::PrivateKey(key),
            None => panic!("no keys found in {:?} (encrypted keys not supported)", pkeyname),
            _ => {}
        }
    };

    GlobalConfiguration {
        tls_cert: certdata,
        tls_pkey: pkeydata,
        openssl_path: String::from("C:\\Program Files\\Git\\usr\\bin\\openssl.exe"),
    }
}


pub fn load_tls_certificate(file_path: &str) -> io::Result<Vec<rustls::Certificate>> {
    let certname = file_path;
    let certfile = fs::File::open(certname)?;
    let certdata = rustls_pemfile::certs(&mut BufReader::new(certfile))
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();
    Ok(certdata)
}


pub fn load_tls_private_key(file_path: &str) -> io::Result<rustls::PrivateKey> {
    let pkeyname = file_path;
    let pkeyfile = fs::File::open(pkeyname)?;
    let mut pkeyreader = BufReader::new(pkeyfile);
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

