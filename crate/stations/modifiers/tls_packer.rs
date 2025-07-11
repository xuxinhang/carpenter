use std::io::{Read, Write};
use rustls::{ServerConnection, ClientConnection, ServerConfig, ClientConfig};
use crate::bridge::{BridgeStation, BridgeResult, BridgeError, BridgeStationTransferRecord};
use crate::common::{Hostname};

const SINGLE_BURST_SIZE_LIMIT: usize = 512 * 1024; // = 512 KB


fn convert_hostname_to_rustls_server_name(h: Hostname) -> rustls::client::ServerName {
    use rustls::client::ServerName;
    match h {
        Hostname::IpAddress(v) =>
            ServerName::IpAddress(v),
        Hostname::DnsName(v) =>
            ServerName::try_from(v.to_string().as_str()).unwrap(),
    }
}


#[derive(PartialEq, Debug)]
enum TlsClosingStage {
    Running,
    PeerSentCloseNotify,
    HereSentCloseNotify,
    BothSentCloseNotify,
    Crushed,
}

impl TlsClosingStage {
    fn peer_closing(&self) -> bool {
        matches!(self, TlsClosingStage::BothSentCloseNotify | TlsClosingStage::PeerSentCloseNotify)
    }
    fn here_closing(&self) -> bool {
        matches!(self, TlsClosingStage::HereSentCloseNotify | TlsClosingStage::BothSentCloseNotify)
    }
    fn both_closed(&self) -> bool {
        matches!(self, TlsClosingStage::BothSentCloseNotify | TlsClosingStage::Crushed)
    }
}


fn append_public_root_certs(root_store: &mut rustls::RootCertStore) {
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
}

pub struct TlsUnpackerStation {
    tls_server: ServerConnection,
    tls_server_closed: TlsClosingStage,
}

pub struct TlsRepackerStation {
    tls_client: ClientConnection,
    tls_client_closed: TlsClosingStage,
}

impl TlsUnpackerStation {
    pub fn new(target_hostname: Hostname, _override_sni: Option<Hostname>) -> Self {
        let host_name = target_hostname.clone();

        use crate::certmgr::certstorage;

        let local_tls_cert_data =
            certstorage::fetch_or_generate_tls_repack_certificate_file(&host_name).unwrap();
        let local_tls_pkey_data =
            certstorage::fetch_or_generate_tls_repack_private_key_file(&host_name).unwrap();

        let local_tls_conf = std::sync::Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(local_tls_cert_data, local_tls_pkey_data)
                .expect("bad local_tls_conf")
        );
        let mut root_store = rustls::RootCertStore::empty();
        append_public_root_certs(&mut root_store);

        let mut local_tls =  ServerConnection::new(local_tls_conf).unwrap();
        local_tls.set_buffer_limit(Some(SINGLE_BURST_SIZE_LIMIT * 2));

        Self {
            tls_server: local_tls,
            tls_server_closed: TlsClosingStage::Running,
        }
    }
}


impl TlsRepackerStation {
    pub fn new(target_hostname: Hostname, override_sni: Option<Hostname>) -> Self {
        let mut root_store = rustls::RootCertStore::empty();
        append_public_root_certs(&mut root_store);

        let mut remote_tls_conf =
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth();
        if override_sni.is_none() {
            remote_tls_conf.enable_sni = false;
        }
        let remote_tls_conf = std::sync::Arc::new(remote_tls_conf);
        let mut remote_tls = ClientConnection::new(
            remote_tls_conf,
            convert_hostname_to_rustls_server_name(override_sni.unwrap_or(target_hostname)),
        ).unwrap();
        remote_tls.set_buffer_limit(Some(SINGLE_BURST_SIZE_LIMIT * 2));
        Self {
            tls_client: remote_tls,
            tls_client_closed: TlsClosingStage::Running,
        }
    }
}


impl BridgeStation for TlsUnpackerStation {
    fn local_write(&mut self, mut buf: &[u8]) -> BridgeResult {
        if !self.tls_server.wants_read() && self.tls_server_closed.both_closed() {
            return Ok(BridgeStationTransferRecord::End);
        }

        if !self.tls_server.wants_read() {
            return Ok(BridgeStationTransferRecord::Some(0));
        }

        let read_tls_result = self.tls_server.read_tls(&mut buf);
        if read_tls_result.is_err() {
            return Err(BridgeError::Protocol("TLS server error: read_tls"));
        }
        let read_tls_size = read_tls_result.unwrap();
        if read_tls_size == 0 {
            return Ok(BridgeStationTransferRecord::Some(0));
        }

        Ok(BridgeStationTransferRecord::Some(read_tls_size))
    }

    fn remote_read(&mut self, buf: &mut [u8]) -> BridgeResult {
        let r = self.tls_server.process_new_packets();
        if r.is_err() {
            return Err(BridgeError::Protocol("TLS server error: process_new_packets"));
        }

        let state = r.unwrap();
        let expected_plaintext_size = state.plaintext_bytes_to_read();
        if state.peer_has_closed() {
            self.tls_server.send_close_notify();
            self.tls_server_closed = TlsClosingStage::BothSentCloseNotify;
        }

        if expected_plaintext_size == 0 && self.tls_server_closed.peer_closing() {
            return Ok(BridgeStationTransferRecord::End);
        }
        if expected_plaintext_size == 0 {
            return Ok(BridgeStationTransferRecord::Some(0));
        }

        // read out plain texts, write them into its pair tls or the buffer. 
        let text_read_size = self.tls_server.reader().read(buf).unwrap();
        Ok(BridgeStationTransferRecord::Some(text_read_size))
    }

    fn remote_write(&mut self, buf: &[u8]) -> BridgeResult {
        if self.tls_server_closed.here_closing() {
            return Ok(BridgeStationTransferRecord::End)
        }

        let text_write_size = self.tls_server.writer().write(buf).unwrap();
        Ok(BridgeStationTransferRecord::Some(text_write_size))
    }

    fn local_read(&mut self, mut buf: &mut [u8]) -> BridgeResult {
        if !self.tls_server.wants_write() && self.tls_server_closed.both_closed() {
            return Ok(BridgeStationTransferRecord::End)
        }
        if !self.tls_server.wants_write() {
            return Ok(BridgeStationTransferRecord::Some(0));
        }
        let write_tls_result = self.tls_server.write_tls(&mut buf);
        if write_tls_result.is_err() {
            return Err(BridgeError::Protocol("Tls Server: local_read -> write_tls"));
        }
        Ok(BridgeStationTransferRecord::Some(write_tls_result.unwrap()))
    }

    fn remote_write_end(&mut self) -> () {
        self.tls_server.send_close_notify();
        self.tls_server_closed = TlsClosingStage::HereSentCloseNotify;
    }

    fn local_write_end(&mut self) -> () {
        self.tls_server_closed = TlsClosingStage::Crushed;
    }

    fn remote_read_end(&mut self) -> () {
        self.remote_write_end()
    }

    fn local_read_end(&mut self) -> () {
        self.local_write_end()
    }
}


impl BridgeStation for TlsRepackerStation {
    fn local_write(&mut self, buf: &[u8]) -> BridgeResult {
        if self.tls_client_closed.here_closing() {
            return Ok(BridgeStationTransferRecord::End);
        }

        let text_size = self.tls_client.writer().write(buf).unwrap();
        Ok(BridgeStationTransferRecord::Some(text_size))
    }

    fn remote_read(&mut self, mut buf: &mut [u8]) -> BridgeResult {
        if !self.tls_client.wants_write() && self.tls_client_closed.both_closed() {
            return Ok(BridgeStationTransferRecord::End);
        }

        if !self.tls_client.wants_write() {
            return Ok(BridgeStationTransferRecord::Some(0));
        }

        let s = self.tls_client.write_tls(&mut buf)
            .map_err(|_e| BridgeError::Protocol("Tls client: write_tls"))?;
        Ok(BridgeStationTransferRecord::Some(s))
    }

    fn remote_write(&mut self, mut buf: &[u8]) -> BridgeResult {
        if !self.tls_client.wants_read() && self.tls_client_closed.both_closed() {
            return Ok(BridgeStationTransferRecord::End);
        }

        if !self.tls_client.wants_read() {
            return Ok(BridgeStationTransferRecord::Some(0));
        }

        let s = self.tls_client.read_tls(&mut buf)
            .map_err(|_e| BridgeError::Protocol("Tls Client: read_tls"))?;
        Ok(BridgeStationTransferRecord::Some(s))
    }

    fn local_read(&mut self, mut buf: &mut [u8]) -> BridgeResult {
        let state = self.tls_client.process_new_packets()
            .map_err(|_e| {
                BridgeError::Protocol("TLS Client: process_new_packets")
            })?;
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
        
        let s = self.tls_client.reader().read(&mut buf)
            .map_err(|_e| BridgeError::Protocol("Tls Client: write_tls"))?;
        Ok(BridgeStationTransferRecord::Some(s))
    }

    fn local_write_end(&mut self) -> () {
        self.tls_client.send_close_notify();
        self.tls_client_closed = TlsClosingStage::HereSentCloseNotify;
    }

    fn remote_write_end(&mut self) -> () {
        self.tls_client_closed = TlsClosingStage::Crushed;
    }

    fn local_read_end(&mut self) -> () {
        self.remote_write_end()
    }

    fn remote_read_end(&mut self) -> () {
        self.local_write_end()
    }
}
