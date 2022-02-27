use std::fs;
use std::io;
use std::io::{BufRead, BufReader};
use crate::uri_match::{HostMatchTree, HostnameMatchTree};


pub struct GlobalConfiguration {
    pub tls_cert: Vec<rustls::Certificate>,
    pub tls_pkey: rustls::PrivateKey,
    pub openssl_path: String,
    pub transformer_host_matcher: HostMatchTree<TransformerAction>,
    pub querier_matcher: HostnameMatchTree<QuerierAction>,
}

pub fn load_default_configuration() -> GlobalConfiguration {
    // load certification file
    let certname = "./certs/default_crt.crt";
    let certfile = fs::File::open(certname).expect("cannot open certificate file");
    let certdata = rustls_pemfile::certs(&mut BufReader::new(certfile))
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();

    // load private key file
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

    // construct global configuration structure
    GlobalConfiguration {
        tls_cert: certdata,
        tls_pkey: pkeydata,
        openssl_path: String::from("C:\\Program Files\\Git\\usr\\bin\\openssl.exe"),
        transformer_host_matcher: load_transformer_matcher(),
        querier_matcher: load_querier_matcher(),
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


/**
 * Transformer config
 * Use different transformers for different domains
 */

fn is_matcher_config_file_line_valid(s: &str) -> bool {
    let s = s.trim_start();
    // ignore blank line
    if s.is_empty() {
        return false;
    }
    // ignore comment line
    if s.starts_with('#') {
        return false;
    }
    true
}

#[derive(Clone)]
pub enum TransformerAction {
    SniTransformer(String),
    DirectTransformer,
}

fn load_transformer_matcher() -> HostMatchTree<TransformerAction> {
    let file_name = "./config/transformer_matcher.txt";
    let reader = BufReader::new(fs::File::open(file_name).unwrap());

    let mut tree = HostMatchTree::new();

    for line in reader.lines() {
        let line = line.unwrap();
        if !is_matcher_config_file_line_valid(&line) {
            continue;
        }

        let (host_str, prof_str) = line.split_once('+').unwrap();
        let host_str = String::from(host_str.trim());
        let mut prof_str = String::from(prof_str.trim());
        prof_str.push(' ');

        let (hostname, port_str) = host_str.rsplit_once(':').unwrap_or((&host_str, "0"));
        let port = port_str.parse().unwrap_or(0) as u16;
        let hostname = hostname.trim();
        let (tf_type, tf_param) = prof_str.split_once(' ').unwrap();
        let prof = match tf_type {
            "sni" => TransformerAction::SniTransformer(tf_param.trim().to_string()),
            _ => TransformerAction::DirectTransformer,
        };

        tree.insert(port, hostname, prof);
    }

    tree
}


#[derive(Clone)]
pub enum QuerierAction {
    To(String),
    Dns(String),
}

fn load_querier_matcher() -> HostnameMatchTree<QuerierAction> {
    let file_name = "./config/querier_matcher.txt";
    let reader = BufReader::new(fs::File::open(file_name).unwrap());

    let mut tree = HostnameMatchTree::new();

    for line in reader.lines() {
        let line = line.unwrap();
        if !is_matcher_config_file_line_valid(&line) {
            continue;
        }

        let (pattern_str, action_str) = line.split_once('+').unwrap();
        let hostname_str = pattern_str.trim();
        let (action_type_str, action_param_str) =
            action_str.split_once(' ').unwrap_or((action_str, ""));
        let action_param_str = action_param_str.trim_start();

        let action = match action_type_str {
            "dns" => QuerierAction::Dns(action_param_str.to_string()),
            "to" => QuerierAction::To(action_param_str.to_string()),
            _ => {
                panic!("Unknown querier pattern.");
            }
        };

        tree.insert(hostname_str, action);
    }

    tree
}
