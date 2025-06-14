use std::cell::RefCell;
use std::cmp::PartialEq;
use std::io::{Read, Write};
use std::collections::VecDeque;
use std::rc::Rc;
use domain::base::Dname;
use crate::bridge::{BridgeError, BridgeResult, BridgeStation, BridgeStationDownwardMessage, BridgeStationMessageDequeAccessor, BridgeStationTransferRecord, BridgeStationUpwardMessage};
use crate::common::{HostName, Hostname, HostAddress};


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
    // forward_end: bool,
    response_message: VecDeque<u8>,
    station_message_upward: BridgeStationMessageDequeAccessor<BridgeStationUpwardMessage>,
    station_message_downward: BridgeStationMessageDequeAccessor<BridgeStationDownwardMessage>,
}

impl HTTPTunnelProtocolStation {
    pub fn new() -> Self {
        Self {
            status: HTTPTunnelStatus::WaitingForLocalMessage,
            tunnel_mode: true,
            forward_message: VecDeque::with_capacity(8*1024),
            response_message: VecDeque::with_capacity(1024),
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
                let r = crate::server::http_proxy_utils::parse_http_proxy_message(
                    self.forward_message.as_slices().0);
                if let Err(e) = r {
                    wd_log::log_warn_ln!("TunnelWaitingForLocalMessage # {}", e);
                    return Err(BridgeError::Protocol("Invalid HTTP Message"));
                }

                let (_msg_header_length, host, tunnel_mode) = r.unwrap();
                self.tunnel_mode = tunnel_mode;
                if self.tunnel_mode == true {
                    self.forward_message.clear(); // TODO
                }

                let host_addr = HostAddress(match host.0 {
                    HostName::IpAddress(s) => Hostname::IpAddress(s),
                    HostName::DomainName(s) => Hostname::DnsName(Dname::vec_from_str(&s).unwrap()),
                }, host.1);

                self.status = HTTPTunnelStatus::WaitingForRemoteConnection;
                self.send_upward_message(BridgeStationUpwardMessage::ServerRequestRemoteConnect(host_addr));
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
                // if empty, prepare response message
                if self.response_message.is_empty() {
                    let byte_message =  match code {
                        200 => if self.tunnel_mode {
                            "HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes()
                        } else {
                            "".as_bytes()
                        }
                        502 => "HTTP/1.1 502 Bad Gateway\r\n\r\n".as_bytes(),
                        _ => unreachable!(),
                    };
                    self.response_message.clear();
                    self.response_message.extend(byte_message);
                }

                // transfer existed response message
                self.response_message.make_contiguous();
                let n = self.response_message.read(buf).map_err(|e| BridgeError::IO(e))?;

                // update status if all response bytes are read out
                if self.response_message.is_empty() {
                    match code {
                        200 => self.status = HTTPTunnelStatus::WaitingForForwardMessageReadOut,
                        502 => self.status = HTTPTunnelStatus::Closed,
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
