use std::io;
use std::io::{Read, Write};
use std::sync::Arc;
use crate::transformer::{TunnelTransformer, TransferResult};
use rustls::{ServerConnection, ClientConnection, ServerConfig, ClientConfig};
use super::buffer::StreamBuffer;


enum ServerName {
    Addr4(std::net::Ipv4Addr),
    Addr6(std::net::Ipv6Addr),
    Domain(String),
}

pub struct ServerNameParseError();

impl std::str::FromStr for ServerName {
    type Err = ServerNameParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
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
    local_tls: ServerConnection,
    remote_tls: ClientConnection,
    transmit_plaintext_buffer: StreamBuffer,
    receive_plaintext_buffer: StreamBuffer,
    transmit_closed: bool,
    receive_closed: bool,
}


impl TunnelSniomitTransformer {
    pub fn new(
        server_str: &str,
        sni_str: &str,
        enable_sni: bool,
    ) -> io::Result<Self> {
        let global_config = crate::global::get_global_config();
        let openssl_path = global_config.core.env_openssl_path.clone();

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

        let (crt_file, key_file) = match server_name {
            ServerName::Addr4(_addr) => {
                unimplemented!();
            }
            ServerName::Addr6(_) => {
                unimplemented!();
            }
            ServerName::Domain(domain) => {
                let domain_name = domain;
                let crt_file_name = format!("_certs/issued/tls_domain__{}__crt.crt", domain_name);
                let csr_file_name = format!("_certs/issued/tls_domain__{}__csr.pem", domain_name);
                let key_file_name = String::from("_certs/root.key.pem");

                if !std::path::Path::new(&crt_file_name).exists() {
                    wd_log::log_info_ln!("Creating TLS certificate ({})...", domain_name);
                    std::process::Command::new(&openssl_path)
                        .args([
                            "req", "-new", "-out", &csr_file_name,
                            "-key", &key_file_name,
                            "-subj", &format!("//X=1/CN={}", domain_name),
                        ])
                        .output()?;
                    std::process::Command::new(&openssl_path)
                        .args([
                            "x509", "-req",
                            "-in", &csr_file_name,
                            "-days", "36500",
                            "-CA", "_certs/root.crt.crt",
                            "-CAkey",  "_certs/root.key.pem",
                            "-out", &crt_file_name,
                            // "-CAcreateserial",
                        ])
                        .output()?;
                    std::fs::remove_file(csr_file_name)?;
                }
                (crt_file_name, key_file_name)
            }
        };

        let local_tls_certificate_data = crate::common::load_tls_certificate(&crt_file)?;
        let local_tls_private_key_data = crate::common::load_tls_private_key(&key_file)?;

        let local_tls_conf = Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(
                    local_tls_certificate_data,
                    local_tls_private_key_data,
                )
                .expect("bad local_tls_conf")
        );
        let mut remote_tls_conf =
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth();
        if !enable_sni {
            remote_tls_conf.enable_sni = false;
        }
        let remote_tls_conf = Arc::new(remote_tls_conf);

        Ok(Self {
            local_tls: ServerConnection::new(local_tls_conf).unwrap(),
            remote_tls: ClientConnection::new(
                remote_tls_conf,
                sni_str.try_into().unwrap_or(
                    server_str.try_into().unwrap_or("localhost".try_into().unwrap()),
                ),
            ).unwrap(),
            transmit_plaintext_buffer: StreamBuffer::new(),
            receive_plaintext_buffer: StreamBuffer::new(),
            transmit_closed: false,
            receive_closed: false,
        })
    }
}


impl TunnelTransformer for TunnelSniomitTransformer {
    fn transmit_write(&mut self, source: &mut dyn Read) -> TransferResult {
        let tls = &mut self.local_tls;

        // we have ensured no plaintext left.
        match tls.read_tls(source) {
            Err(e) => {
                self.transmit_closed = true;
                return (Err(format!("{:?}", e)), true);
            }
            Ok(read_size) => {
                if read_size == 0 {
                    self.transmit_closed = true;
                }

                match tls.process_new_packets() {
                    Err(e) => {
                        self.transmit_closed = true;
                        return (Err(format!("{:?}", e)), true);
                    }
                    Ok(tls_state) => {
                        let expected_plaintext_size = tls_state.plaintext_bytes_to_read();
                        if expected_plaintext_size != 0 {
                            let r = &mut tls.reader();
                            let mut current_plaintext_size = 0;
                            while current_plaintext_size < expected_plaintext_size {
                                match self.transmit_plaintext_buffer.read_from(r) {
                                    (Some(Err(e)), _) => {
                                        self.transmit_closed = true;
                                        return (Err(format!("{:?}", e)), true);
                                    }
                                    (Some(Ok(n)), _) => {
                                        if n == 0 { self.transmit_closed = true; }
                                        current_plaintext_size += n;
                                        // return (Ok(n), self.transmit_closed);
                                    },
                                    (None, _) => {
                                        // return (Ok(0), self.transmit_closed);
                                    }
                                }
                            }
                        }
                    }
                }

                return (Ok(read_size), self.transmit_closed);
            }
        }
    }

    fn transmit_read(&mut self, target: &mut dyn Write) -> TransferResult {
        let tls = &mut self.remote_tls;
        let mut tls_to_close = false;

        loop {
            // first try to write_tls directly
            if tls.wants_write() {
                match tls.write_tls(target) {
                    Err(e) => {
                        return (Err(format!("{:?}", e)), true);
                    },
                    Ok(n) => {
                        return (Ok(n), !tls.wants_write() && tls_to_close);
                    },
                }
            }

            if tls_to_close {
                return (Ok(0), true);
            }

            // load more plaintext if there is nothing for write_tls
            match self.transmit_plaintext_buffer.write_into(&mut tls.writer()) {
                (Some(Err(e)), _) => {
                    return (Err(format!("{:?}", e)), true);
                }
                (Some(Ok(n)), pending) => {
                    if pending == 0 && self.transmit_closed {
                        tls_to_close = true;
                        tls.send_close_notify();
                    } else if n == 0 {
                        return (Ok(0), false);
                    }
                }
                (None, pending) => {
                    if pending == 0 && self.transmit_closed {
                        tls_to_close = true;
                        tls.send_close_notify();
                    } else {
                        return (Ok(0), false);
                    }
                }
            }
        }
    }

    fn receive_write(&mut self, source: &mut dyn Read) -> TransferResult {
        let tls = &mut self.remote_tls;
        // if !tls.wants_read() {

        // we have ensured no plaintext left.
        match tls.read_tls(source) {
            Err(e) => {
                self.receive_closed = true;
                return (Err(format!("{:?}", e)), true);
            }
            Ok(read_size) => {
                if read_size == 0 {
                    self.receive_closed = true;
                }

                match tls.process_new_packets() {
                    Err(e) => {
                        self.receive_closed = true;
                        return (Err(format!("{:?}", e)), true);
                    }
                    Ok(tls_state) => {
                        let expected_plaintext_size = tls_state.plaintext_bytes_to_read();
                        if expected_plaintext_size != 0 {
                            let r = &mut tls.reader();
                            let mut current_plaintext_size = 0;
                            while current_plaintext_size < expected_plaintext_size {
                                match self.receive_plaintext_buffer.read_from(r) {
                                    (Some(Err(e)), _) => {
                                        self.receive_closed = true;
                                        return (Err(format!("{:?}", e)), true);
                                    }
                                    (Some(Ok(n)), _) => {
                                        if n == 0 { self.receive_closed = true; }
                                        current_plaintext_size += n;
                                    }
                                    (None, _) => {}
                                }
                            }
                        }
                    }
                }

                return (Ok(read_size), self.receive_closed);
            }
        }
    }

    fn receive_read(&mut self, target: &mut dyn Write) -> TransferResult {
        let tls = &mut self.local_tls;
        let mut tls_to_close = false;

        loop {
            // first try to write_tls directly
            if tls.wants_write() {
                match tls.write_tls(target) {
                    Err(e) => {
                        return (Err(format!("{:?}", e)), true);
                    },
                    Ok(n) => {
                        return (Ok(n), !tls.wants_write() && tls_to_close);
                    },
                }
            }

            if tls_to_close {
                return (Ok(0), true);
            }

            // load more plaintext if there is nothing for write_tls
            match self.receive_plaintext_buffer.write_into(&mut tls.writer()) {
                (Some(Err(e)), _) => {
                    return (Err(format!("{:?}", e)), true);
                }
                (Some(Ok(n)), pending) => {
                    if pending == 0 && self.receive_closed {
                        tls_to_close = true;
                        tls.send_close_notify();
                    } else if n == 0 {
                        return (Ok(0), false);
                    }
                }
                (None, pending) => {
                    if pending == 0 && self.receive_closed {
                        tls_to_close = true;
                        tls.send_close_notify();
                    } else {
                        return (Ok(0), false);
                    }
                }
            }
        }
    }
}
