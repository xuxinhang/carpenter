use std::io;
use std::io::{Read, Write};
use std::sync::Arc;
use std::rc::Rc;
use crate::transformer::TunnelTransformer;
use crate::configuration::GlobalConfiguration;
use rustls::{ServerConnection, ClientConnection, ServerConfig, ClientConfig, IoState};


enum ServerName {
    Addr4(std::net::Ipv4Addr),
    Addr6(std::net::Ipv6Addr),
    Domain(String),
}

pub struct ServerNameParseError();

impl std::str::FromStr for ServerName {
    type Err = ServerNameParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // let server_addr4 = s.parse() as Result<std::net::Ipv4Addr, _>;
        if let Ok(ip_addr) = s.parse() {
            return Ok(ServerName::Addr4(ip_addr));
        } else if let Ok(ip_addr) = s.parse() {
            return Ok(ServerName::Addr6(ip_addr));
        } else if let Ok(domain) = s.parse() {
            return Ok(ServerName::Domain(domain));
        } else {
            return Err(ServerNameParseError());
        }
    }
}



pub struct TunnelSniomitTransformer {
    global_configuration: Rc<GlobalConfiguration>,
    local_tls: ServerConnection,
    local_tls_closed: bool,
    local_tls_error: bool,
    // local_tls_conf: Arc<ServerConfig>,
    remote_tls: ClientConnection,
    remote_tls_closed: bool,
    remote_tls_error: bool,
    // remote_tls_conf: Arc<ClientConfig>,
}

impl TunnelSniomitTransformer {
    pub fn new(global_configuration: Rc<GlobalConfiguration>, server_str: &str) -> io::Result<Self> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS
                .0
                .iter()
                .map(|ta| {
                    rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                })
        );

        let server_name = server_str.parse()
            .unwrap_or(ServerName::Addr4("127.0.0.1".parse().unwrap()));

        let mut cfg_content = String::new();
        cfg_content.push_str("[req]\n");
        cfg_content.push_str("prompt = no\n");
        cfg_content.push_str("distinguished_name = req_distinguished_name\n");
        cfg_content.push_str("req_extensions = reqext\n");
        cfg_content.push_str("\n");
        cfg_content.push_str("[req_distinguished_name]\n");
        cfg_content.push_str("C  = CN\n");
        cfg_content.push_str("ST = CQ\n");
        cfg_content.push_str("L  = CQ\n");
        cfg_content.push_str("O  = Xuxinhang\n");
        cfg_content.push_str("OU = Xuxinhang\n");

        let (crt_file, key_file) = match server_name {
            ServerName::Addr4(_addr) => {
                let crt_file_name = format!("tls_certs/tls_addr4__{}__crt.crt", server_str);
                let csr_file_name = format!("tls_certs/tls_addr4__{}__csr.pem", server_str);
                let key_file_name = format!("tls_certs/tls_addr4__{}__key.pem", server_str);
                if !std::path::Path::new(&crt_file_name).exists() {
                    println!("Creating TLS certificate (Addr4).");
                    let mut content = cfg_content.clone();
                    content.push_str(&format!("CN = {}\n", server_str));
                    content.push_str("\n");
                    content.push_str("[reqext]");
                    content.push_str(&format!("subjectAltName = IP.1:{}", server_str));
                    content.push_str("\n");
                    // content.push_str("subjectAltName = DNS.1:*.zhihu.com,DNS.2:sina.cn");

                    let config_file_name = "tls_certs/_config.tmp";
                    let mut config_file = std::fs::File::create(config_file_name)?;
                    config_file.write(content.as_bytes())?;

                    std::process::Command::new(&global_configuration.openssl_path)
                        .arg(format!(
                            " req -newkey rsa:2048 -nodes -keyout {} -out {} -config {}",
                            key_file_name, csr_file_name, config_file_name
                        ))
                        .output()?;

                    std::process::Command::new(&global_configuration.openssl_path)
                        .arg(format!(
                            " x509 -req -in {} -CA {} -CAkey {} -out {} -CAcreateserial -extfile {} -extensions reqext",
                            csr_file_name, "root_crt.pem", "root_key.pem", crt_file_name, config_file_name
                        ))
                        .output()?;
                }
                (crt_file_name, key_file_name)
            }
            ServerName::Addr6(_) => {
                panic!("Not implemented."); // TODO
            }
            ServerName::Domain(domain) => {
                let domain_name = domain;
                let crt_file_name = format!("tls_certs/tls_domain__{}__crt.crt", domain_name);
                let csr_file_name = format!("tls_certs/tls_domain__{}__csr.pem", domain_name);
                let key_file_name = String::from("certs/tls_default_key.pem");

                if !std::path::Path::new(&crt_file_name).exists() {
                    println!("Creating TLS certificate ({})...", domain_name);
                    std::process::Command::new(&global_configuration.openssl_path)
                        .args([
                            "req", "-new", "-key", &key_file_name,
                            "-out", &csr_file_name,
                            "-subj", &format!("//X=1/CN={}", domain_name),
                        ])
                        .output()?;
                    std::process::Command::new(&global_configuration.openssl_path)
                        .args([
                            "x509", "-req",
                            "-in", &csr_file_name,
                            "-CA", "certs/root_crt.pem",
                            "-CAkey",  "certs/root_key.pem",
                            "-out", &crt_file_name,
                            "-CAcreateserial",
                        ])
                        .output()?;
                    std::fs::remove_file(csr_file_name)?;
                }
                (crt_file_name, key_file_name)
            }
        };

        let local_tls_certificate_data = crate::configuration::load_tls_certificate(&crt_file)?;
        let local_tls_private_key_data = crate::configuration::load_tls_private_key(&key_file)?;

        let local_tls_conf = Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(
                    local_tls_certificate_data, // global_configuration.tls_cert.clone(),
                    local_tls_private_key_data, // global_configuration.tls_pkey.clone(),
                )
                .expect("bad local_tls_conf")
        );
        let remote_tls_conf =
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth();
        // remote_tls_conf.enable_sni = false;
        let remote_tls_conf = Arc::new(remote_tls_conf);

        Ok(Self {
            local_tls: ServerConnection::new(local_tls_conf).unwrap(),
            local_tls_closed: false,
            local_tls_error: false,
            remote_tls: ClientConnection::new(
                remote_tls_conf,
                server_str.try_into().unwrap_or("example.com".try_into().unwrap()), // TODO
                // "static.zhihu.com".try_into().unwrap(),
            ).unwrap(),
            remote_tls_closed: false,
            remote_tls_error: false,
            // remote_tls_conf,
            global_configuration,
        })
    }
}


impl TunnelTransformer for TunnelSniomitTransformer {
    fn transmit_write(&mut self, source: &mut impl Read) -> io::Result<Option<usize>> {
        // println!("> transmit_write");
        let tls = &mut self.local_tls;
        if !tls.wants_read() {
            return Ok(None);
        }
        let _tls_read_size = tls.read_tls(source)?;
        let tls_process_result = tls.process_new_packets();
        if tls_process_result.is_err() {
            self.local_tls_error = true;
            println!("local_tls_error {:?}", tls_process_result.unwrap_err());
            return Ok(Some(0));
        }
        let tls_state = tls_process_result.unwrap();
        if tls_state.peer_has_closed() {
            self.remote_tls.send_close_notify();
            self.local_tls_closed = true;
        }
        let expected_plaintext_size = tls_state.plaintext_bytes_to_read();
        if expected_plaintext_size > 0 {
            let mut accu_number = 0;
            let mut buf = vec![0u8; 4096];
            while accu_number < expected_plaintext_size {
                let n = tls.reader().read(&mut buf)?;
                buf.truncate(n);
                accu_number += n;
                let tls = &mut self.remote_tls;
                let _write_size = tls.writer().write(&buf)?;
            }
        }
        if self.local_tls_closed {
            println!("local_tls_closed");
            return Ok(Some(0));
        } else {
            if expected_plaintext_size == 0 {
                return Ok(None);
            } else {
                return Ok(Some(expected_plaintext_size));
            }
        }
    }

    fn transmit_read(&mut self, target: &mut impl Write) -> io::Result<Option<usize>> {
        // println!("> transmit_read");
        let tls = &mut self.remote_tls;
        if !tls.wants_write() {
            if self.local_tls_closed || self.local_tls_error {
                return Ok(Some(0));
            } else {
                return Ok(None);
            }
        }
        let n = tls.write_tls(target)?;
        Ok(Some(n))
    }

    fn receive_write(&mut self, source: &mut impl Read) -> io::Result<Option<usize>> {
        // println!("> receive_write");
        let tls = &mut self.remote_tls;
        if !tls.wants_read() {
            return Ok(None);
        }
        tls.read_tls(source)?;
        let tls_process_result = tls.process_new_packets();
        if tls_process_result.is_err() {
            self.remote_tls_error = true;
            println!("remote_tls_error {:?}", tls_process_result.unwrap_err());
            return Ok(Some(0));
        }
        let tls_state = tls_process_result.unwrap();
        if tls_state.peer_has_closed() {
            println!("receive write peer has closed");
            self.remote_tls_closed = true;
            self.local_tls.send_close_notify();
        }
        let expected_plaintext_size = tls_state.plaintext_bytes_to_read();
        if expected_plaintext_size > 0 {
            let mut accu_count = 0;
            let mut buf = vec![0u8; 4096];
            while accu_count < expected_plaintext_size {
                let n = tls.reader().read(&mut buf)?;
                buf.truncate(n);
                accu_count += n;
                let tls = &mut self.local_tls;
                tls.writer().write(&buf)?;
            }
        }
        if self.remote_tls_closed {
            println!("remote_tls_closed");
            return Ok(Some(0));
        } else {
            if expected_plaintext_size == 0 {
                return Ok(None);
            } else {
                return Ok(Some(expected_plaintext_size));
            }
        }
    }

    fn receive_read(&mut self, target: &mut impl Write) -> io::Result<Option<usize>> {
        // println!("> receive_read {}", self.remote_tls_closed);
        let tls = &mut self.local_tls;
        if !tls.wants_write() {
            if self.remote_tls_closed || self.remote_tls_error {
                return Ok(Some(0));
            } else {
                return Ok(None);
            }
        }
        let n = tls.write_tls(target)?;
        Ok(Some(n))
    }
}




