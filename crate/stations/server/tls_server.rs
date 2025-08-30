use std::io::{Read, Write};
use rustls::{ServerConnection, ServerConfig};
use crate::bridge::{BridgeStation, BridgeResult, BridgeError, BridgeStationTransferRecord};
use crate::certmgr::certstorage;
use crate::common::{Hostname};
use crate::helper::tls_struct::TlsClosingStage;

const SINGLE_BURST_SIZE_LIMIT: usize = 512 * 1024; // = 512 KB


pub struct TlsUniversalServerStation {
    tls_server: ServerConnection,
    tls_server_closed: TlsClosingStage,
}


impl TlsUniversalServerStation {
    pub fn new(target_hostname: Hostname) -> Self {
        let host_name = target_hostname.clone();

        println!("Creating TLS universal server station: {:?}", host_name);

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

        let mut local_tls =  ServerConnection::new(local_tls_conf).unwrap();
        local_tls.set_buffer_limit(Some(SINGLE_BURST_SIZE_LIMIT * 2));

        Self {
            tls_server: local_tls,
            tls_server_closed: TlsClosingStage::Running,
        }
    }
}



impl BridgeStation for TlsUniversalServerStation {
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
            println!("TLS server error: {:?}", r.err().unwrap());
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

