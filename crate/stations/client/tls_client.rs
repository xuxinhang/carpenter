use std::{fs, io};
use std::io::{Read, Write};
use std::sync::Arc;
use rustls::{ClientConnection, ServerName};
use crate::bridge::{BridgeStation, BridgeResult, BridgeError, BridgeStationTransferRecord};
use crate::certmgr::certstorage::ROOT_CA_CERTIFICATE_PATH;
use crate::common::{Hostname};
use crate::helper::tls_struct::TlsClosingStage;

const SINGLE_BURST_SIZE_LIMIT: usize = 512 * 1024; // = 512 KB


pub struct TlsUniversalClientStation {
    tls_client: ClientConnection,
    tls_client_closed: TlsClosingStage,
}

impl TlsUniversalClientStation {
    pub fn new(server_hostname: Hostname) -> Self {
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

        fn get_other_trust_anchor_data(crt_file_name: &str) -> io::Result<Option<Vec<u8>>> {
            let file_path_prefix = "";
            let crt_file_name = format!("{}{}", file_path_prefix, crt_file_name);

            let certfile = fs::File::open(crt_file_name)?;
            let items = rustls_pemfile::read_all(&mut io::BufReader::new(certfile))?;

            let der = match items.first().unwrap() {
                rustls_pemfile::Item::X509Certificate(dat) => {
                    // println!("X509: {:?}", String::from_utf8_lossy(&dat));
                    // let mut file = fs::File::create("./test.crt")?;
                    // file.write_all(&dat).unwrap();
                    dat
                },
               _ => return Ok(None),
            };

            Ok(Some(der.clone()))

            // let ta = webpki::TrustAnchor::try_from_cert_der(&der).unwrap();
            // let anchor = rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            //     ta.subject,
            //     ta.spki,
            //     ta.name_constraints,
            //     );
            // println!("{}", String::from_utf8_lossy(ta.subject));
            // Ok(Some(anchor))
        }

        if let Some(anchor) = get_other_trust_anchor_data(ROOT_CA_CERTIFICATE_PATH).unwrap() {
            let lst = [anchor];
            root_store.add_parsable_certificates(&lst);
        }

        let tls_client_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        println!("ServerName: {:?}", ServerName::try_from(server_hostname.to_string().as_str()).unwrap());

        let mut local_tls =  ClientConnection::new(
            Arc::new(tls_client_config),
            ServerName::try_from(server_hostname.to_string().as_str()).unwrap(),
        ).unwrap();
        local_tls.set_buffer_limit(Some(SINGLE_BURST_SIZE_LIMIT * 2));

        Self {
            tls_client: local_tls,
            tls_client_closed: TlsClosingStage::Running,
        }
    }
}


// two kinds of closing connection
//   call (local|remote)_(write|read)_end(),
//   check peer_has_closed()

impl BridgeStation for TlsUniversalClientStation {
    fn get_flag(&self) -> &'static str {
        "TlsUniversalClientStation"
    }
    
    fn remote_write(&mut self, mut buf: &[u8]) -> BridgeResult {
        if !self.tls_client.wants_read() && self.tls_client_closed.both_closed() {
            return Ok(BridgeStationTransferRecord::End);
        }

        if !self.tls_client.wants_read() {
            return Ok(BridgeStationTransferRecord::Some(0));
        }

        let read_tls_result = self.tls_client.read_tls(&mut buf);
        if read_tls_result.is_err() {
            return Err(BridgeError::Protocol("TLS client error: read_tls"));
        }
        let read_tls_size = read_tls_result.unwrap();
        if read_tls_size == 0 {
            return Ok(BridgeStationTransferRecord::Some(0));
        }

        Ok(BridgeStationTransferRecord::Some(read_tls_size))
    }

    fn local_read(&mut self, buf: &mut [u8]) -> BridgeResult {
        let r = self.tls_client.process_new_packets();
        if r.is_err() {
            println!("TLS client error: {:?}", r.err().unwrap());
            return Err(BridgeError::Protocol("TLS client error: process_new_packets"));
        }

        let state = r.unwrap();
        let expected_plaintext_size = state.plaintext_bytes_to_read();
        if state.peer_has_closed() {
            self.tls_client.send_close_notify();
            self.tls_client_closed = TlsClosingStage::BothSentCloseNotify;
        }

        if expected_plaintext_size == 0 && self.tls_client_closed.peer_closing() {
            return Ok(BridgeStationTransferRecord::End);
        }
        if expected_plaintext_size == 0 {
            return Ok(BridgeStationTransferRecord::Some(0));
        }

        // read out plain texts, write them into its pair tls or the buffer. 
        let text_read_size = self.tls_client.reader().read(buf).unwrap();
        Ok(BridgeStationTransferRecord::Some(text_read_size))
    }

    fn local_write(&mut self, buf: &[u8]) -> BridgeResult {
        if self.tls_client_closed.here_closing() {
            return Ok(BridgeStationTransferRecord::End)
        }

        let text_write_size = self.tls_client.writer().write(buf).unwrap();
        Ok(BridgeStationTransferRecord::Some(text_write_size))
    }

    fn remote_read(&mut self, mut buf: &mut [u8]) -> BridgeResult {
        if !self.tls_client.wants_write() && self.tls_client_closed.both_closed() {
            return Ok(BridgeStationTransferRecord::End)
        }
        if !self.tls_client.wants_write() {
            return Ok(BridgeStationTransferRecord::Some(0));
        }
        let write_tls_result = self.tls_client.write_tls(&mut buf);
        if write_tls_result.is_err() {
            return Err(BridgeError::Protocol("Tls Server: local_read -> write_tls"));
        }
        Ok(BridgeStationTransferRecord::Some(write_tls_result.unwrap()))
    }

    fn local_write_end(&mut self) -> () {
        self.tls_client.send_close_notify();
        self.tls_client_closed = TlsClosingStage::HereSentCloseNotify;
    }

    fn remote_write_end(&mut self) -> () {
        self.tls_client_closed = TlsClosingStage::Crushed;
    }

    fn remote_read_end(&mut self) -> () {
        self.remote_write_end()
    }

    fn local_read_end(&mut self) -> () {
        self.local_write_end()
    }
}

