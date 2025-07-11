use std::collections::VecDeque;
use std::io::{Read, Write};
use crate::bridge::{BridgeError, BridgeResult, BridgeStation, BridgeStationDownwardMessage, BridgeStationMessageDequeAccessor, BridgeStationTransferRecord, BridgeStationUpwardMessage};
use crate::common::HostAddress;

pub struct HttpTunnelProtocolClientStation {
    station_message_upward: BridgeStationMessageDequeAccessor<BridgeStationUpwardMessage>,
    station_message_downward: BridgeStationMessageDequeAccessor<BridgeStationDownwardMessage>,
    status: HttpTunnelProtocolClientStatus,
    target_host_address: HostAddress,
    request_message: VecDeque<u8>,
    response_message: VecDeque<u8>,
}


pub enum HttpTunnelProtocolClientStatus {
    WaitingToRequest,
    WaitingForResponse,
    Running,
    Closed,
}


impl HttpTunnelProtocolClientStation {
    pub fn new(target_host_address: HostAddress) -> Self {
        Self {
            station_message_upward: BridgeStationMessageDequeAccessor::null(),
            station_message_downward: BridgeStationMessageDequeAccessor::null(),
            status: HttpTunnelProtocolClientStatus::WaitingToRequest,
            target_host_address,
            request_message: VecDeque::new(),
            response_message: VecDeque::new(),
        }
    }

    fn send_upward_message(&mut self, message: BridgeStationUpwardMessage) {
        self.station_message_upward.push(message);
    }
}

impl BridgeStation for HttpTunnelProtocolClientStation {
    fn local_write(&mut self, _buf: &[u8]) -> BridgeResult {
        match self.status {
            HttpTunnelProtocolClientStatus::Running => unreachable!(),
            HttpTunnelProtocolClientStatus::Closed => Ok(BridgeStationTransferRecord::End),
            _ => Ok(BridgeStationTransferRecord::Some(0)),
        }
    }

    fn local_read(&mut self, _buf: &mut [u8]) -> BridgeResult {
        match self.status {
            HttpTunnelProtocolClientStatus::Running => unreachable!(),
            HttpTunnelProtocolClientStatus::Closed => Ok(BridgeStationTransferRecord::End),
            _ => Ok(BridgeStationTransferRecord::Some(0)),
        }
    }

    fn remote_write(&mut self, buf: &[u8]) -> BridgeResult {
        match self.status {
            HttpTunnelProtocolClientStatus::WaitingForResponse => {
                assert!(self.response_message.is_empty());
                let n = self.response_message.write(buf).unwrap();

                let l = self.response_message.len();
                if l >= 4
                    && self.response_message[l-4] == b'\r' && self.response_message[l-3] == b'\n'
                    && self.response_message[l-2] == b'\r' && self.response_message[l-1] == b'\n' {
                    // parse this http response message
                    let mut resp_headers = Vec::new();
                    let mut resp = httparse::Response::new(resp_headers.as_mut());

                    self.response_message.make_contiguous();
                    let res = resp.parse(self.response_message.as_slices().0);
                    match res {
                        Ok(httparse::Status::Complete(_)) => {
                            if resp.code == Some(200) {
                                self.status = HttpTunnelProtocolClientStatus::Running;
                                self.send_upward_message(BridgeStationUpwardMessage::ServerRequestBypassForever);
                            } else {
                                self.status = HttpTunnelProtocolClientStatus::Closed;
                            }
                        }
                        Ok(httparse::Status::Partial) | Err(_) =>
                            return Err(BridgeError::Protocol("Failed to parse HTTP response")),
                    }
                }
                    
                Ok(BridgeStationTransferRecord::Some(n))
            }
            HttpTunnelProtocolClientStatus::WaitingToRequest => Ok(BridgeStationTransferRecord::Some(0)),
            HttpTunnelProtocolClientStatus::Running => unreachable!(),
            HttpTunnelProtocolClientStatus::Closed => Ok(BridgeStationTransferRecord::End),
        }
    }

    fn remote_read(&mut self, buf: &mut [u8]) -> BridgeResult {
        match self.status {
            HttpTunnelProtocolClientStatus::WaitingToRequest => {
                if self.request_message.is_empty() {
                    let host_address_literal = format!(
                        "{}:{}",
                        self.target_host_address.0.to_string(),
                        self.target_host_address.1,
                    );
                    let http_message =
                        format!("CONNECT {} HTTP/1.1\r\n", host_address_literal)
                            + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0\r\n"
                            + "Proxy-Connection: keep-alive\r\n"
                            + "Connection: keep-alive\r\n"
                            + &format!("Host: {}\r\n", host_address_literal)
                            + "\r\n";
                    self.request_message.clear();
                    self.request_message.extend(http_message.as_bytes());
                }

                let n = self.request_message.read(buf)
                    .map_err(|_| BridgeError::Protocol("Failed to read request message"))?;
                if self.request_message.is_empty() {
                    self.status = HttpTunnelProtocolClientStatus::WaitingForResponse;
                }
                Ok(BridgeStationTransferRecord::Some(n))
            }
            HttpTunnelProtocolClientStatus::WaitingForResponse => Ok(BridgeStationTransferRecord::Some(0)),
            HttpTunnelProtocolClientStatus::Running => unreachable!(),
            HttpTunnelProtocolClientStatus::Closed => Ok(BridgeStationTransferRecord::End),
        }
    }

    fn local_write_end(&mut self) -> () {
        self.status = HttpTunnelProtocolClientStatus::Closed;
    }

    fn local_read_end(&mut self) -> () {
        self.status = HttpTunnelProtocolClientStatus::Closed;
    }

    fn remote_write_end(&mut self) -> () {
        self.status = HttpTunnelProtocolClientStatus::Closed;
    }

    fn remote_read_end(&mut self) -> () {
        self.status = HttpTunnelProtocolClientStatus::Closed;
    }

    fn set_message_queue(&mut self,
                         downward: BridgeStationMessageDequeAccessor<BridgeStationDownwardMessage>,
                         upward: BridgeStationMessageDequeAccessor<BridgeStationUpwardMessage>) {
        self.station_message_downward = downward;
        self.station_message_upward = upward;
    }

    // fn notify_message(&mut self) {
    //     let message_queue = &self.station_message_downward;
    //     if message_queue.peek().is_none() {
    //         return ();
    //     }
    //     let (_, msg) = message_queue.consume();
    //     match msg {
    //         _ => {},
    //     }
    // }
}

