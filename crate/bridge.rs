use std::io::{Read, Write};
use std::{io, iter, mem};
use std::collections::VecDeque;
use std::rc::Rc;
use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr};
use mio::event::Event;
use mio::{Interest, Token};
use mio::net::TcpStream;
use crate::common::{HostAddress, Hostname};
use crate::dnsresolver::{DnsQueier, DnsResolveCallback};
use crate::event_loop::{EventHandler, EventLoop, EventRegistryIntf};
use crate::stations::remote::base::RemoteLinkGuide;

pub type BridgeResult = Result<BridgeStationTransferRecord, BridgeError>;
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum BridgeStationTransferRecord { Some(usize), Wait, End }
// pub type BridgeStationTransferRecord = Option<usize>;

impl BridgeStationTransferRecord {
    pub fn is_end(&self) -> bool {
        *self == Self::End
    }
    pub fn is_some(&self) -> bool {
        if let Self::Some(_) = self {
            true
        } else {
            false
        }
    }
    pub fn is_wait(&self) -> bool {
        *self == Self::Wait
    }
}

#[derive(Debug)]
pub enum BridgeError {
    IO(io::Error),
    Protocol(&'static str),
    Other(&'static str),
}


pub struct BridgeStationMessageDequeAccessor<T: Clone> {
    pub id: usize,
    deque_ref: Rc<RefCell<Vec<(usize, T)>>>,
    null_mode: bool,
}

const BRIDGE_STATION_LOCAL_TERMINAL_STATION_ID: usize = 10;
const BRIDGE_STATION_REMOTE_TERMINAL_STATION_ID: usize = 11;
const BRIDGE_STATION_GENERAL_STATION_ID_BASE: usize = 20;

impl <T: Clone> BridgeStationMessageDequeAccessor<T> {
    pub fn from(new_id: usize, mrc: &Self) -> Self {
        Self {
            id: new_id,
            deque_ref: mrc.deque_ref.clone(),
            null_mode: mrc.null_mode,
        }
    }

    pub fn create(id: usize) -> Self {
        Self {
            id,
            deque_ref: Rc::new(RefCell::new(Vec::with_capacity(4))),
            null_mode: false,
        }
    }

    pub fn clone_with_new_id(&self, new_id: usize) -> Self {
        Self::from(new_id, self)
    }

    pub fn null() -> Self {
        Self {
            id: 0,
            deque_ref: Rc::new(RefCell::new(Vec::with_capacity(0))),
            null_mode: true,
        }
    }

    pub fn push(&mut self, mes: T) {
        if self.null_mode {
            unreachable!();
        }
        self.deque_ref.borrow_mut().push((self.id, mes))
    }

    pub fn peek(&self) -> Option<(usize, T)> {
        self.deque_ref.borrow().first().map(|x| (x.0, x.1.clone()))
    }

    pub fn consume(&self) -> (usize, T) {
        self.deque_ref.borrow_mut().remove(0)
    }
}


#[derive(Clone)]
pub enum BridgeStationUpwardMessage {
    ServerRequestBypassForever,
    ServerRequestRemoteConnect(HostAddress),
    ClientReportRemoteHandshakeFinished(bool),
}

#[derive(Clone)]
pub enum BridgeStationDownwardMessage {
    ServerKnowRemoteHandshakeFinished(bool),
}


pub trait BridgeStation {
    fn local_write(&mut self, buf: &[u8]) -> BridgeResult;
    fn local_read(&mut self, buf: &mut [u8]) -> BridgeResult;
    fn remote_write(&mut self, buf: &[u8]) -> BridgeResult;
    fn remote_read(&mut self, buf: &mut [u8]) -> BridgeResult;

    fn local_write_end(&mut self) -> () {}
    fn local_read_end(&mut self) -> () {}
    fn remote_write_end(&mut self) -> () {}
    fn remote_read_end(&mut self) -> () {}

    fn set_message_queue(&mut self,
                         downward: BridgeStationMessageDequeAccessor<BridgeStationDownwardMessage>,
                         upward: BridgeStationMessageDequeAccessor<BridgeStationUpwardMessage>) {
        ()
    }

    fn notify_message(&mut self) {
        ()
    }
}


struct BridgeNullRemoteTerminal {}

impl BridgeStation for BridgeNullRemoteTerminal {
    fn local_write(&mut self, buf: &[u8]) -> BridgeResult {
        assert_eq!(buf.len(), 0);
        Ok(BridgeStationTransferRecord::Some(0))
    }

    fn local_read(&mut self, buf: &mut [u8]) -> BridgeResult {
        Ok(BridgeStationTransferRecord::Some(0))
    }

    fn remote_write(&mut self, buf: &[u8]) -> BridgeResult {
        assert_eq!(buf.len(), 0);
        Ok(BridgeStationTransferRecord::Some(0))
    }

    fn remote_read(&mut self, buf: &mut [u8]) -> BridgeResult {
        Ok(BridgeStationTransferRecord::Some(0))
    }
}

pub struct BridgeTCPStreamLocalTerminal {
    stream: TcpStream,
    listener_token: Token,
    listener_registered: usize,
}

impl BridgeTCPStreamLocalTerminal {
    pub fn from_stream(stream: TcpStream, listener_token: Token) -> Self {
        Self {
            stream,
            listener_token,
            listener_registered: 0,
        }
    }
}

impl BridgeStation for BridgeTCPStreamLocalTerminal {
    fn local_write(&mut self, buf: &[u8]) -> BridgeResult {
        unreachable!()
    }

    fn local_read(&mut self, buf: &mut [u8]) -> BridgeResult {
        unreachable!()
    }

    fn remote_write(&mut self, buf: &[u8]) -> BridgeResult {
        let res = match self.stream.write(buf) {
            Ok(0) => {
                wd_log::log_debug_ln!("BridgeTCPStreamLocalTerminal -> remote_write: Ok(0)");
                Ok(BridgeStationTransferRecord::End)
            },
            Ok(n) => {
                self.stream.flush().unwrap();
                wd_log::log_debug_ln!("BridgeTCPStreamLocalTerminal -> remote_write: Ok(n={:?})", n);
                Ok(BridgeStationTransferRecord::Some(n))
            },
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => {
                    wd_log::log_debug_ln!("BridgeTCPStreamLocalTerminal -> remote_write: WouldBlock");
                    Ok(BridgeStationTransferRecord::Wait)
                }
                _ => Err(BridgeError::IO(e)),
            }
        };
        res
    }

    fn remote_read(&mut self, buf: &mut [u8]) -> BridgeResult {
        let res = match self.stream.read(buf) {
            Ok(0) => {
                wd_log::log_debug_ln!("BridgeTCPStreamLocalTerminal -> remote_read: Ok(0)");
                Ok(BridgeStationTransferRecord::End)
            },
            Ok(n) => {
                wd_log::log_debug_ln!("BridgeTCPStreamLocalTerminal -> remote_read: Ok(n={})", n);
                Ok(BridgeStationTransferRecord::Some(n))
            },
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => {
                    wd_log::log_debug_ln!("BridgeTCPStreamLocalTerminal -> remote_read: WouldBlock");
                    Ok(BridgeStationTransferRecord::Wait)
                }
                _ => Err(BridgeError::IO(e)),
            }
        };
        res
    }
}

struct BridgeTCPStreamRemoteTerminal {
    stream: TcpStream,
    listener_token: Token,
    listener_registered: usize,
}

impl BridgeTCPStreamRemoteTerminal {
    pub fn from_token(stream: TcpStream, listener_token: Token) -> Self {
        Self {
            stream,
            listener_token,
            listener_registered: 0,
        }
    }
}

impl BridgeStation for BridgeTCPStreamRemoteTerminal {
    fn local_write(&mut self, buf: &[u8]) -> BridgeResult {
        let res = match self.stream.write(buf) {
            Ok(0) => {
                wd_log::log_debug_ln!("BridgeTCPStreamRemoteTerminal -> local_write: Ok(0)");
                Ok(BridgeStationTransferRecord::End)
            },
            Ok(n) => {
                wd_log::log_debug_ln!("BridgeTCPStreamRemoteTerminal -> local_write: Ok(n=)");
                Ok(BridgeStationTransferRecord::Some(n))
            },
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => {
                    wd_log::log_debug_ln!("BridgeTCPStreamRemoteTerminal -> local_write: WouldBlock");
                    Ok(BridgeStationTransferRecord::Wait)
                }
                _ => Err(BridgeError::IO(e)),
            }
        };
        res
    }

    fn local_read(&mut self, buf: &mut [u8]) -> BridgeResult {
        let res = match self.stream.read(buf) {
            Ok(0) => {
                wd_log::log_debug_ln!("BridgeTCPStreamRemoteTerminal -> local_read: Ok(0)");
                Ok(BridgeStationTransferRecord::End)
            },
            Ok(n) => {
                wd_log::log_debug_ln!("BridgeTCPStreamRemoteTerminal -> local_read: Ok(n={}) ", n);
                Ok(BridgeStationTransferRecord::Some(n))
            },
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => {
                    wd_log::log_debug_ln!("BridgeTCPStreamRemoteTerminal -> local_read: WouldBlock");
                    Ok(BridgeStationTransferRecord::Wait)
                }
                _ => Err(BridgeError::IO(e)),
            }
        };
        res
    }

    fn remote_write(&mut self, buf: &[u8]) -> BridgeResult {
        unreachable!()
    }

    fn remote_read(&mut self, buf: &mut [u8]) -> BridgeResult {
        unreachable!()
    }
}


pub struct BridgeChain {
    local_terminal: BridgeTCPStreamLocalTerminal,
    local_terminal_read_snapshot: BridgeStationTransferRecord,
    local_terminal_write_snapshot: BridgeStationTransferRecord,
    remote_terminal: Option<BridgeTCPStreamRemoteTerminal>,
    remote_terminal_read_snapshot: BridgeStationTransferRecord,
    remote_terminal_write_snapshot: BridgeStationTransferRecord,
    stations: Vec<(usize, Box<dyn BridgeStation>)>,
    station_id_generator: Box<dyn Iterator<Item=usize>>,
    buffers: Vec<(BridgeBuffer, BridgeBuffer)>, // 0: to local, 1: to remote
    local_terminal_next_interest: Option<Interest>,
    remote_terminal_next_interest: Option<Interest>,
    pub public_upward_message_queue: BridgeStationMessageDequeAccessor<BridgeStationUpwardMessage>,
    pub public_downward_message_queue: BridgeStationMessageDequeAccessor<BridgeStationDownwardMessage>,
    remote_link_guide: Option<RemoteLinkGuide>,
}

impl BridgeChain {
    pub fn from_existed(
        mut local_terminal: BridgeTCPStreamLocalTerminal,
        mut initial_stations: Vec<Box<dyn BridgeStation>>,
    ) -> Self {
        let station_count = initial_stations.len();
        let buffer_count = station_count + 1;

        let upward_queue = BridgeStationMessageDequeAccessor::create(0);
        let downward_queue = BridgeStationMessageDequeAccessor::create(0);

        local_terminal.set_message_queue(
            downward_queue.clone_with_new_id(BRIDGE_STATION_LOCAL_TERMINAL_STATION_ID),
            upward_queue.clone_with_new_id(BRIDGE_STATION_LOCAL_TERMINAL_STATION_ID),
        );

        // let mut init_buffers = Vec::with_capacity(buffer_count);
        // for _ in 0..buffer_count {
        //     init_buffers.push((BridgeBuffer::new(), BridgeBuffer::new()));
        // }
        // let mut init_stations : Vec<(usize, Box<dyn BridgeStation>)> =
        //     initial_stations.into_iter().enumerate()
        //         .map(|(i, s)| (i+ BRIDGE_STATION_GENERAL_STATION_ID_BASE, s))
        //         .collect();
        //
        // init_stations.iter_mut().for_each(|(si, sb)|
        //     sb.set_message_queue(
        //         downward_queue.clone_with_new_id(*si),
        //         upward_queue.clone_with_new_id(*si),
        //     ));
        //
        let zero_stations = Vec::with_capacity(station_count);
        let mut zero_buffers = Vec::with_capacity(buffer_count);
        zero_buffers.push((BridgeBuffer::new(), BridgeBuffer::new()));

        let terminal_initial_snapshot = BridgeStationTransferRecord::Wait;

        let mut bridge = Self {
            local_terminal,
            local_terminal_read_snapshot: terminal_initial_snapshot,
            local_terminal_write_snapshot: terminal_initial_snapshot,
            remote_terminal: None,
            remote_terminal_read_snapshot: terminal_initial_snapshot,
            remote_terminal_write_snapshot: terminal_initial_snapshot,
            station_id_generator: Box::new(iter::successors(Some(300), |&n| Some(n + 1))),
            stations: zero_stations,
            buffers: zero_buffers,
            public_upward_message_queue: upward_queue,
            public_downward_message_queue: downward_queue,
            local_terminal_next_interest: None,
            remote_terminal_next_interest: None,
            remote_link_guide: None,
        };

        initial_stations.into_iter().enumerate().for_each(|(_, sb)| {
            bridge.append_station(sb);
        });

        bridge
    }

    fn assign_remote_terminal(
        &mut self,
        remote_terminal: BridgeTCPStreamRemoteTerminal,
        force_release_connected_message: bool
    ) {
        self.remote_terminal = Some(remote_terminal);
        self.remote_terminal.as_mut().unwrap().set_message_queue(
            self.public_downward_message_queue.clone_with_new_id(BRIDGE_STATION_REMOTE_TERMINAL_STATION_ID),
            self.public_upward_message_queue.clone_with_new_id(BRIDGE_STATION_REMOTE_TERMINAL_STATION_ID),
        );

        if force_release_connected_message {
            self.public_downward_message_queue.push(
                BridgeStationDownwardMessage::ServerKnowRemoteHandshakeFinished(true));
        }
    }

    fn flush_once(&mut self) -> Result<(usize, bool), BridgeError> {
        let mut total_size = 0;
        macro_rules! handle_buffer_result {
            ($expr:expr) => {
                match ($expr)? {
                    BridgeStationTransferRecord::Some(n) => {
                        total_size += n;
                        BridgeStationTransferRecord::Some(n)
                    }
                    x => x,
                }
            }
        }

        macro_rules! handle_message_result {
            ($expr:expr) => {
                if $expr == true { // have to end flush right now
                    return Ok((total_size, true));
                }
            }
        }

        macro_rules! merge_terminal_snapshot {
            ($var:expr, $next:expr) => {
                if $var.is_end() && !$next.is_end() {
                    unreachable!();
                }
                $var = $next;
            };
        }

        let is_terminal_snapshot_operable =
            |s: Option<usize>| s.map_or(false, |x| x != 0);

        // local terminal
        {
            macro_rules! get_remote_side_buffers { () => {&mut self.buffers[0]} }
            if self.local_terminal_read_snapshot.is_some() {
                let remote_side_buffers = get_remote_side_buffers!();
                self.local_terminal.notify_message();
                merge_terminal_snapshot!(
                    self.local_terminal_read_snapshot,
                    handle_buffer_result!(
                        remote_side_buffers.1.read_from(&mut self.local_terminal, true)));
                handle_message_result!(
                    self.handle_upward_message_queue(BRIDGE_STATION_LOCAL_TERMINAL_STATION_ID));
            }
            if self.local_terminal_write_snapshot.is_some() {
                let remote_side_buffers = get_remote_side_buffers!();
                self.local_terminal.notify_message();
                merge_terminal_snapshot!(
                    self.local_terminal_write_snapshot,
                    handle_buffer_result!(
                        remote_side_buffers.0.write_into(&mut self.local_terminal, true)));
                handle_message_result!(
                    self.handle_upward_message_queue(BRIDGE_STATION_LOCAL_TERMINAL_STATION_ID));
            }
        }

        // middle station
        for j in 0..self.stations.len() {
            let current_station_id = self.stations[j].0;
            macro_rules! get_current_station {() => {self.stations[j].1.as_mut()};}
            macro_rules! get_local_side_buffers {() => {&mut self.buffers[j]};}
            {
                let current_station = get_current_station!();
                let local_side_buffers = get_local_side_buffers!();
                current_station.notify_message();
                handle_buffer_result!(local_side_buffers.1.write_into(current_station, false));
                handle_message_result!(
                    self.handle_upward_message_queue(current_station_id));
            }
            {
                let current_station = get_current_station!();
                let local_side_buffers = get_local_side_buffers!();
                current_station.notify_message();
                handle_buffer_result!(local_side_buffers.0.read_from(current_station, false));
                self.handle_upward_message_queue(current_station_id);
            }
            macro_rules! get_remote_side_buffers {() => {&mut self.buffers[j+1]};}
            {
                let current_station = get_current_station!();
                let remote_side_buffers = get_remote_side_buffers!();
                current_station.notify_message();
                handle_buffer_result!(remote_side_buffers.1.read_from(current_station, true));
                handle_message_result!(
                    self.handle_upward_message_queue(current_station_id));
            }
            {
                let current_station = get_current_station!();
                let remote_side_buffers = get_remote_side_buffers!();
                current_station.notify_message();
                handle_buffer_result!(remote_side_buffers.0.write_into(current_station, true));
                handle_message_result!(
                    self.handle_upward_message_queue(current_station_id));
            }
        }

        // remote terminal
        {
            let mut null_terminal = BridgeNullRemoteTerminal {};
            macro_rules! get_maybe_terminal {
                () => {
                    self.remote_terminal.as_mut()
                        .map_or(&mut null_terminal as &mut dyn BridgeStation,|s| s)
                }
            }
            macro_rules! get_local_side_buffers { () => {self.buffers.last_mut().unwrap()} }
            if self.remote_terminal_write_snapshot.is_some() {
                let local_side_buffers = get_local_side_buffers!();
                let maybe_terminal = get_maybe_terminal!();
                maybe_terminal.notify_message();
                merge_terminal_snapshot!(
                    self.remote_terminal_write_snapshot,
                    handle_buffer_result!(local_side_buffers.1.write_into(maybe_terminal, false)));
                handle_message_result!(
                    self.handle_upward_message_queue(BRIDGE_STATION_REMOTE_TERMINAL_STATION_ID));
            }
            if self.remote_terminal_read_snapshot.is_some() {
                let local_side_buffers = get_local_side_buffers!();
                let maybe_terminal = get_maybe_terminal!();
                maybe_terminal.notify_message();
                merge_terminal_snapshot!(
                    self.remote_terminal_read_snapshot,
                    handle_buffer_result!(local_side_buffers.0.read_from(maybe_terminal, false)));
                handle_message_result!(
                    self.handle_upward_message_queue(BRIDGE_STATION_REMOTE_TERMINAL_STATION_ID));
            }
        }

        Ok((total_size, false))
    }

    fn handle_upward_message_queue(&mut self, expected_station_id: usize) -> bool {
        let queue = &mut self.public_upward_message_queue;
        if queue.peek().is_none() {
            return false;
        }

        let (message_station_id, message) = queue.consume();
        assert_eq!(expected_station_id, message_station_id);

        let mut have_to_skip_loop = false;
        match message {
            BridgeStationUpwardMessage::ClientReportRemoteHandshakeFinished(res) => {
                self.public_downward_message_queue.push(
                    BridgeStationDownwardMessage::ServerKnowRemoteHandshakeFinished(res));
            },
            BridgeStationUpwardMessage::ServerRequestBypassForever => {
                self.remove_station(message_station_id);
                have_to_skip_loop = true;
            },
            BridgeStationUpwardMessage::ServerRequestRemoteConnect(host_addr) => {
                let guide = crate::stations::remote::base::get_default_remote_link(host_addr);
                assert!(self.remote_link_guide.is_none());
                self.remote_link_guide = Some(guide);
                // create and handle remote TcpStream later
            },
        }
        have_to_skip_loop
    }

    fn append_station(&mut self, mut new_station: Box<dyn BridgeStation>) {
        let new_station_id: usize = self.station_id_generator.next().unwrap();

        new_station.set_message_queue(
            self.public_downward_message_queue.clone_with_new_id(new_station_id),
            self.public_upward_message_queue.clone_with_new_id(new_station_id),
        );
        self.stations.push((new_station_id, new_station));
        self.buffers.push((BridgeBuffer::new(), BridgeBuffer::new()));
    }

    fn remove_station(&mut self, station_id: usize) {
        let station_index = self.stations.iter()
            .position(|(si, sb)| *si == station_id).unwrap();
        self.stations.remove(station_index);

        let local_side_buffers = &self.buffers[station_index];
        let remote_side_buffers = &self.buffers[station_index+1];
        let merged_buffers = (
            BridgeBuffer::merge(&local_side_buffers.0, &remote_side_buffers.0),
            BridgeBuffer::merge(&remote_side_buffers.1, &local_side_buffers.1)
        );
        self.buffers.splice(station_index..station_index+2, std::iter::once(merged_buffers));
    }

    fn do_loop (&mut self) {
        self.local_terminal_read_snapshot = BridgeStationTransferRecord::Some(1);
        self.local_terminal_write_snapshot = BridgeStationTransferRecord::Some(1);
        self.remote_terminal_read_snapshot = BridgeStationTransferRecord::Some(1);
        self.remote_terminal_write_snapshot = BridgeStationTransferRecord::Some(1);

        // 1. do transfer among terminals and stations.
        loop {
            let res = self.flush_once();
            if let Err(e) = res {
                wd_log::log_warn_ln!("BridgeChain.do_loop // {:?}", e);
                return;
            }
            let (flush_size, flush_incomplete) = res.unwrap();
            if flush_size == 0 && flush_incomplete == false {
                break;
            }
        }

        // 2. check terminals' latest snapshot
        let is_record_fully_operated = |s|
            match s {
                BridgeStationTransferRecord::Some(n) if n > 0 => false,
                _ => false,
            };
            // if let BridgeStationTransferRecord::Some(_) = s { true } else { false };
        if is_record_fully_operated(self.local_terminal_read_snapshot)
            || is_record_fully_operated(self.local_terminal_write_snapshot)
            || is_record_fully_operated(self.remote_terminal_read_snapshot)
            || is_record_fully_operated(self.remote_terminal_write_snapshot) {
            unreachable!();
        }
    }
}


impl EventHandler for BridgeChain {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        self.collect(registry)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        self.collect(registry)
    }

    fn collect(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        self.local_terminal_next_interest =
            match (self.local_terminal_read_snapshot, self.local_terminal_write_snapshot)  {
                (BridgeStationTransferRecord::Wait, BridgeStationTransferRecord::Wait) => Some(Interest::WRITABLE | Interest::READABLE),
                (_, BridgeStationTransferRecord::Wait) => Some(Interest::WRITABLE),
                (BridgeStationTransferRecord::Wait, _) => Some(Interest::READABLE),
                _ => None,
            };

        self.remote_terminal_next_interest =
            match (self.remote_terminal_read_snapshot, self.remote_terminal_write_snapshot)  {
                (BridgeStationTransferRecord::Wait, BridgeStationTransferRecord::Wait) => Some(Interest::WRITABLE | Interest::READABLE),
                (_, BridgeStationTransferRecord::Wait) => Some(Interest::WRITABLE),
                (BridgeStationTransferRecord::Wait, _) => Some(Interest::READABLE),
                _ => None,
            };

        {
            if let Some(interest) = self.local_terminal_next_interest {
                if self.local_terminal.listener_registered == 0 {
                    registry.register(&mut self.local_terminal.stream, self.local_terminal.listener_token, interest)?;
                } else {
                    registry.reregister(&mut self.local_terminal.stream, self.local_terminal.listener_token, interest)?;
                }
                self.local_terminal.listener_registered += 1;
            }
        }

        if let Some(ref mut remote_terminal) = self.remote_terminal {
            if let Some(interest) = self.remote_terminal_next_interest {
                if remote_terminal.listener_registered == 0 {
                    registry.register(&mut remote_terminal.stream, remote_terminal.listener_token, interest)?;
                } else {
                    registry.reregister(&mut remote_terminal.stream, remote_terminal.listener_token, interest)?;
                }
                remote_terminal.listener_registered += 1;
            }
        }

        Ok(())
    }

    fn handle(mut self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        self.do_loop();

        if self.remote_link_guide.is_some() && self.remote_terminal.is_none() {
            let direct_hostname = match self.remote_link_guide.as_ref().unwrap().stream_target.0 {
                Hostname::IpAddress(ref addr) => Hostname::IpAddress(addr.clone()),
                Hostname::DnsName(ref domain) => Hostname::DnsName(domain.clone()),
                // TODO: direct ip access :: return ip.clone()
            };

            match &direct_hostname {
                Hostname::IpAddress(addr) => {
                    let fake_handler = DnsQueryOnLoadHandler { hanged_bridge: self };
                    let fake_handler = Box::new(fake_handler);
                    fake_handler.ready(Some(addr.clone()), event_loop); // TODO
                }
                Hostname::DnsName(domain) => {
                    let query_handler = DnsQueryOnLoadHandler { hanged_bridge: self };
                    let querier = DnsQueier::new2(domain);
                    querier.query(Box::new(query_handler), event_loop);
                }
            }
            return;
        }

        // local and remote terminal event
        event_loop.reregister(self).unwrap();
    }
}


struct DnsQueryOnLoadHandler {
    hanged_bridge: Box<BridgeChain>
}

impl DnsResolveCallback for DnsQueryOnLoadHandler {
    fn ready(self: Box<Self>, ip: Option<IpAddr>, event_loop: &mut EventLoop) {
        let mut hanged_bridge = self.hanged_bridge;

        macro_rules! report_failure {
            ($handshake_result:expr) => {
                hanged_bridge.public_downward_message_queue.push(
                    BridgeStationDownwardMessage::ServerKnowRemoteHandshakeFinished(false)
                );
                event_loop.reregister(hanged_bridge);
                return;
            };
        }

        if ip.is_none() {
            report_failure!(false);
        }

        let stream = TcpStream::connect(SocketAddr::new(
            ip.unwrap(),
            (&hanged_bridge).remote_link_guide.as_ref().unwrap().stream_target.1)
        );
        if stream.is_err() {
            report_failure!(false);
        }

        let stream_token = event_loop.token.get();
        let next_handler = RemoteTcpStreamOnConnectedHandler {
            hanged_bridge,
            remote_stream: stream.unwrap(),
            remote_stream_token: stream_token,
        };
        event_loop.register(Box::new(next_handler)).unwrap();
    }
}

struct RemoteTcpStreamOnConnectedHandler {
    hanged_bridge: Box<BridgeChain>,
    remote_stream_token: Token,
    remote_stream: TcpStream,
}

impl EventHandler for RemoteTcpStreamOnConnectedHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        registry.register(&mut self.remote_stream, self.remote_stream_token, Interest::WRITABLE)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        let mut hanged_bridge = self.hanged_bridge;
        
        let remote_terminal = BridgeTCPStreamRemoteTerminal {
            stream: self.remote_stream,
            listener_token: self.remote_stream_token,
            listener_registered: 1, // shouldn't be 0, because we just registered it.
        };
        hanged_bridge.assign_remote_terminal(remote_terminal, true);

        let mut guide = hanged_bridge.remote_link_guide.take().unwrap();
        let extended_stations = mem::replace(&mut guide.stations, vec![]);
        extended_stations.into_iter().for_each(|sb| {
            hanged_bridge.append_station(sb);
        });
        hanged_bridge.remote_link_guide = Some(guide);
        
        hanged_bridge.handle(event, event_loop);
        // event_loop.reregister(hanged_bridge).unwrap();
        // TODO
    }
}



const STREAM_BUFFER_MAX_CAPACITY: usize = 4 * 1024 * 1024;
const STREAM_BUFFER_INIT_CAPACITY: usize = 16 * 1024;

pub struct BridgeBuffer {
    deque: VecDeque<u8>,
    max_capacity: usize,
    data_in_end: bool,
    data_out_end: bool,
}

impl BridgeBuffer {
    pub fn new() -> Self {
        Self {
            deque: VecDeque::with_capacity(STREAM_BUFFER_INIT_CAPACITY),
            max_capacity: STREAM_BUFFER_MAX_CAPACITY,
            data_in_end: false,
            data_out_end: false,
        }
    }
    
    pub fn merge(buf_head: &Self, buf_tail: &Self) -> Self {
        let next_max_capacity = std::cmp::max(
            STREAM_BUFFER_MAX_CAPACITY,
            buf_head.deque.len() + buf_tail.deque.len(),
        );
        let mut next_deque = VecDeque::with_capacity(next_max_capacity);
        next_deque.extend(&buf_head.deque);
        next_deque.extend(&buf_tail.deque);
        assert!(buf_head.data_in_end == false && buf_tail.data_out_end == false);
        Self {
            deque: next_deque,
            max_capacity: next_max_capacity,
            data_in_end: buf_tail.data_in_end,
            data_out_end: buf_head.data_out_end,
        }
    }

    pub fn wants_read(&self) -> usize {
        self.max_capacity - self.deque.len()
    }

    pub fn wants_write(&self) -> usize {
        self.deque.len()
    }

    pub fn read_from(&mut self, reader: &mut dyn BridgeStation, side: bool) -> BridgeResult {
        if self.data_out_end {
            if !side {
                reader.local_read_end()
            } else {
                reader.remote_read_end()
            }
            return Ok(BridgeStationTransferRecord::End);
        }

        if self.wants_read() == 0 {
            wd_log::log_debug_ln!("BridgeBuffer -> read_from -> wants_read() == 0");
            return Ok(BridgeStationTransferRecord::Some(0));
        }

        let mut data = vec![0; self.wants_read()]; // TODO: faster?
        let res = if !side {
            reader.local_read(&mut data)
        } else {
            reader.remote_read(&mut data)
        };

        match res {
            Ok(BridgeStationTransferRecord::Some(size)) => {
                self.deque.extend(data.iter().take(size));
                Ok(BridgeStationTransferRecord::Some(size))
            }
            Ok(BridgeStationTransferRecord::End) => {
                self.data_in_end = true;
                Ok(BridgeStationTransferRecord::End)
            }
            _ => res,
        }
    }

    pub fn write_into(&mut self, writter: &mut dyn BridgeStation, side: bool) -> BridgeResult {
        if self.wants_read() == 0 && self.data_in_end {
            if !side {
                writter.local_write_end()
            } else {
                writter.remote_write_end()
            }
            return Ok(BridgeStationTransferRecord::End);
        }

        if self.wants_write() == 0 {
            return Ok(BridgeStationTransferRecord::Some(0))
        }

        let (head, _tail) = self.deque.as_slices();
        let res = if !side {
            writter.local_write(head)
        } else {
            writter.remote_write(head)
        };

        match res {
            Ok(BridgeStationTransferRecord::Some(size)) => {
                self.deque.drain(..size);
                Ok(BridgeStationTransferRecord::Some(size))
            }
            Ok(BridgeStationTransferRecord::End) => {
                self.data_out_end = true;
                Ok(BridgeStationTransferRecord::End)
            }
            _ => res,
        }
    }
}



