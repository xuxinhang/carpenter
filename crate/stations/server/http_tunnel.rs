use std::cell::RefCell;
use std::cmp::PartialEq;
use std::io::{Read, Write};
use std::collections::VecDeque;
use std::rc::Rc;
use std::str::FromStr;
use crate::authorization::verifiers::{AuthenticationVerifier};
use crate::authorization::protocol::httpauth::{HttpAuthenticationServerManager, HttpAuthorizationCredential};
use crate::bridge::{BridgeError, BridgeResult, BridgeStation, BridgeStationDownwardMessage, BridgeStationMessageDequeAccessor, BridgeStationTransferRecord, BridgeStationUpwardMessage};
use crate::helper::{find_http_message_header_ending, HttpRequestMessage};

#[derive(PartialEq, Debug)]
enum HTTPTunnelStatus {
    WaitingForLocalMessage,
    WaitingForRemoteConnection,
    WaitingToResponseToLocal(u16),
    WaitingForForwardMessageReadOut,
    Established,
    Closed,
}

pub struct HTTPTunnelProtocolStation  {
    status: HTTPTunnelStatus,
    tunnel_mode: bool,
    forward_message: VecDeque<u8>,
    response_message: VecDeque<u8>,
    authentication_manager: HttpAuthenticationServerManager,
    station_message_upward: BridgeStationMessageDequeAccessor<BridgeStationUpwardMessage>,
    station_message_downward: BridgeStationMessageDequeAccessor<BridgeStationDownwardMessage>,
}

impl HTTPTunnelProtocolStation {
    pub fn new(
        base_authentication_manager: Rc<RefCell<Box<dyn AuthenticationVerifier>>>,
    ) -> Self {
        Self {
            status: HTTPTunnelStatus::WaitingForLocalMessage,
            tunnel_mode: true,
            forward_message: VecDeque::with_capacity(8*1024),
            response_message: VecDeque::with_capacity(1024),
            authentication_manager: HttpAuthenticationServerManager::new(base_authentication_manager),
            station_message_upward: BridgeStationMessageDequeAccessor::null(),
            station_message_downward: BridgeStationMessageDequeAccessor::null(),
        }
    }

    fn send_upward_message(&mut self, message: BridgeStationUpwardMessage) {
        self.station_message_upward.push(message);
    }
}

impl BridgeStation for HTTPTunnelProtocolStation {
    fn local_write(&mut self, buf: &[u8]) -> BridgeResult {
        match self.status {
            HTTPTunnelStatus::WaitingForLocalMessage => {
                let res = self.forward_message.write(buf);
                self.forward_message.make_contiguous();

                match find_http_message_header_ending(self.forward_message.as_slices().0) {
                    None => {}, // still waiting for the complete HTTP header.
                    Some(header_len_expected) => {
                        let (message, header_len) =
                            HttpRequestMessage::from_bytes(self.forward_message.as_slices().0)
                                .map_err(|_| BridgeError::Protocol("Invalid HTTP Message"))?;
                        assert_eq!(header_len, header_len_expected);

                        // verify Proxy-Authorization
                        let field = message.headers.iter()
                            .find(|h| h.0 == "Proxy-Authorization");
                        let maybe_credential =
                            if let Some(f) = field {
                                let cred =
                                    HttpAuthorizationCredential::from_str(&*String::from_utf8_lossy(f.1.as_slice()))
                                        .map_err(|_| BridgeError::Protocol("Invalid Proxy-Authorization"))?;
                                Some(cred)
                            } else {
                                None
                            };
                        let has_authentication_field = maybe_credential.is_some();
                        let check_result =
                            self.authentication_manager.check_credentials(maybe_credential);
                        match check_result {
                            Ok(true) => {
                                self.tunnel_mode = message.is_tunnel_mode();
                                if self.tunnel_mode {
                                    self.forward_message.clear();
                                } else {
                                    // TODO: rename http header
                                }
                                let host_addr = message.get_host_addr();
                                if host_addr.is_err() {
                                    return Err(BridgeError::Protocol("Invalid Host Address"));
                                }
                                let host_addr = host_addr.unwrap();
                                self.send_upward_message(BridgeStationUpwardMessage::ServerRequestRemoteConnect(host_addr));
                                self.status = HTTPTunnelStatus::WaitingForRemoteConnection;
                            }
                            Ok(false) | Err(_) => {
                                self.forward_message.clear();
                                if has_authentication_field {
                                    self.status = HTTPTunnelStatus::WaitingToResponseToLocal(404);
                                } else {
                                    self.status = HTTPTunnelStatus::WaitingToResponseToLocal(407);
                                }
                            }
                        }
                    }
                }

                Ok(BridgeStationTransferRecord::Some(res.unwrap()))
            }
            HTTPTunnelStatus::WaitingToResponseToLocal(_) => Err(BridgeError::Protocol("")),
            HTTPTunnelStatus::WaitingForRemoteConnection => Err(BridgeError::Protocol("")),
            HTTPTunnelStatus::WaitingForForwardMessageReadOut => Ok(BridgeStationTransferRecord::Some(0)),
            HTTPTunnelStatus::Closed => Ok(BridgeStationTransferRecord::End),
            HTTPTunnelStatus::Established => unreachable!(),
        }
    }

    fn local_read(&mut self, buf: &mut [u8]) -> BridgeResult {
        match self.status {
            HTTPTunnelStatus::WaitingToResponseToLocal(code) => {
                // if empty, prepare a response message
                if self.response_message.is_empty() {
                    let literal_message =  match code {
                        200 => if self.tunnel_mode {
                            "HTTP/1.1 200 Connection Established\r\n\r\n".to_string()
                        } else {
                            "".to_string()
                        }
                        502 => "HTTP/1.1 502 Bad Gateway\r\n\r\n".to_string(),
                        404 => "HTTP/1.1 404 Not Found\r\n\r\n".to_string(),
                        407 => {
                            let challenge_string: Vec<_> = self.authentication_manager.get_challenges().iter()
                                .map(|c| c.get_http_string())
                                .collect();
                            format!(
                                concat!(
                                    "HTTP/1.1 407 Proxy Authentication Required\r\n",
                                    "Content-Length: 0\r\n",
                                    "Proxy-Authenticate: {}\r\n\r\n",
                                ),
                                challenge_string.join(", ")
                            )
                        },
                        _ => unreachable!(),
                    };
                    self.response_message.clear();
                    self.response_message.extend(literal_message.as_bytes());
                }

                // transfer existed response message
                self.response_message.make_contiguous();
                let n = self.response_message.read(buf).map_err(|e| BridgeError::IO(e))?;

                // update status if all response bytes are read out
                if self.response_message.is_empty() {
                    match code {
                        200 => self.status = HTTPTunnelStatus::WaitingForForwardMessageReadOut,
                        502 | 404 => self.status = HTTPTunnelStatus::Closed,
                        407 => self.status = HTTPTunnelStatus::WaitingForLocalMessage,
                        _ => unreachable!(),
                    }
                }
                Ok(BridgeStationTransferRecord::Some(n))
            }
            HTTPTunnelStatus::WaitingForLocalMessage => Ok(BridgeStationTransferRecord::Some(0)),
            HTTPTunnelStatus::WaitingForRemoteConnection => Ok(BridgeStationTransferRecord::Some(0)),
            HTTPTunnelStatus::WaitingForForwardMessageReadOut => Ok(BridgeStationTransferRecord::Some(0)),
            HTTPTunnelStatus::Closed => Ok(BridgeStationTransferRecord::End),
            HTTPTunnelStatus::Established => unreachable!(),
        }
    }

    fn remote_write(&mut self, _buf: &[u8]) -> BridgeResult {
        match self.status {
            HTTPTunnelStatus::WaitingToResponseToLocal(_) => Ok(BridgeStationTransferRecord::Some(0)),
            HTTPTunnelStatus::WaitingForLocalMessage => Ok(BridgeStationTransferRecord::Some(0)),
            HTTPTunnelStatus::WaitingForRemoteConnection => Ok(BridgeStationTransferRecord::Some(0)),
            HTTPTunnelStatus::WaitingForForwardMessageReadOut => Ok(BridgeStationTransferRecord::Some(0)),
            HTTPTunnelStatus::Closed => Ok(BridgeStationTransferRecord::End),
            HTTPTunnelStatus::Established => unreachable!(),
        }
    }

    fn remote_read(&mut self, buf: &mut [u8]) -> BridgeResult {
        match self.status {
            HTTPTunnelStatus::WaitingForForwardMessageReadOut => {
                self.forward_message.make_contiguous();
                let n= self.forward_message.read(buf).unwrap();
                if self.forward_message.is_empty() {
                    self.send_upward_message(BridgeStationUpwardMessage::ServerRequestBypassForever);
                    self.status = HTTPTunnelStatus::Established;
                }
                Ok(BridgeStationTransferRecord::Some(n))
            },
            HTTPTunnelStatus::WaitingToResponseToLocal(_) => Ok(BridgeStationTransferRecord::Some(0)),
            HTTPTunnelStatus::WaitingForLocalMessage => Ok(BridgeStationTransferRecord::Some(0)),
            HTTPTunnelStatus::WaitingForRemoteConnection => Ok(BridgeStationTransferRecord::Some(0)),
            HTTPTunnelStatus::Closed => Ok(BridgeStationTransferRecord::End),
            HTTPTunnelStatus::Established => unreachable!(),
        }
    }

    fn local_write_end(&mut self) -> () {
        self.status = HTTPTunnelStatus::Closed;
    }

    fn local_read_end(&mut self) -> () {
        self.status = HTTPTunnelStatus::Closed;
    }

    fn remote_write_end(&mut self) -> () {
        self.status = HTTPTunnelStatus::Closed;
    }

    fn remote_read_end(&mut self) -> () {
        self.status = HTTPTunnelStatus::Closed;
    }

    fn set_message_queue(&mut self,
                         downward: BridgeStationMessageDequeAccessor<BridgeStationDownwardMessage>,
                         upward: BridgeStationMessageDequeAccessor<BridgeStationUpwardMessage>) {
        self.station_message_downward = downward;
        self.station_message_upward = upward;
    }

    fn notify_message(&mut self) {
        let message_queue = &self.station_message_downward;
        if message_queue.peek().is_none() {
            return ();
        }

        let (_, msg) = message_queue.consume();
        match msg {
            BridgeStationDownwardMessage::ServerKnowRemoteHandshakeFinished(result) => {
                if self.status != HTTPTunnelStatus::WaitingForRemoteConnection {
                    self.status = HTTPTunnelStatus::Closed;
                } else if result {
                    self.status = HTTPTunnelStatus::WaitingToResponseToLocal(200);
                } else {
                    self.status = HTTPTunnelStatus::WaitingToResponseToLocal(502);
                }
            }
        }
    }
}
