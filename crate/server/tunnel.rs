use std::rc::Rc;
use std::cell::RefCell;
use std::io::{self, Read, Write};
use mio::{Interest, Token};
use mio::event::{Event};
use mio::net::TcpStream;
use crate::event_loop::{EventHandler, EventLoop, EventRegistryIntf};
use crate::transformer::{TransformerUnit, TransformerUnitError};
use crate::common::HostAddr;


pub struct TunnelMeta {
    pub _remote_host: HostAddr,
    pub http_forward_mode: bool,
}


#[inline(always)]
fn would_block(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::WouldBlock
}

#[inline(always)]
fn connection_error(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::ConnectionAborted => true,
        ErrorKind::ConnectionReset => true,
        _ => false,
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum ConnStatus { Available, Block, Shutdown, Error }


pub struct EstablishedTunnel {
    transformers: Vec<Box<dyn TransformerUnit>>,
    _meta: TunnelMeta,
    //
    local_conn: TcpStream,
    local_token: Token,
    local_wsta: ConnStatus,
    local_rsta: ConnStatus,
    //
    remote_conn: TcpStream,
    remote_token: Token,
    remote_wsta: ConnStatus,
    remote_rsta: ConnStatus,
    //
    transmit_buffers: Vec<(Vec<u8>, Interest)>,
    receive_buffers: Vec<(Vec<u8>, Interest)>,
}


impl EstablishedTunnel {
    pub fn new(
        transformers: Vec<Box<dyn TransformerUnit>>,
        meta: TunnelMeta,
        local_conn: TcpStream,
        local_token: Token,
        remote_conn: TcpStream,
        remote_token: Token,
        early_message: Option<&[u8]>, // TODO: add a parameter indicating its position
    ) -> Self {
        let tf_number = transformers.len();
        let mut transmit_buffers = Vec::with_capacity(tf_number+1);
        let mut receive_buffers = Vec::with_capacity(tf_number+1);
        let default_interest = Interest::READABLE | Interest::WRITABLE;
        for _ in 0..(tf_number+1) {
            transmit_buffers.push((Vec::with_capacity(32 * 1024), default_interest.clone()));
            receive_buffers.push((Vec::with_capacity(32 * 1024), default_interest.clone()));
        }

        // if need, insert early messages into the given buffer.
        if let Some(msg) = early_message {
            transmit_buffers[1].0.write(msg).unwrap();
        }

        Self {
            transformers,
            _meta: meta,
            local_token,
            local_conn,
            local_wsta: ConnStatus::Available,
            local_rsta: ConnStatus::Available,
            remote_token,
            remote_conn,
            remote_wsta: ConnStatus::Available,
            remote_rsta: ConnStatus::Available,
            transmit_buffers,
            receive_buffers,
        }
    }

    pub fn process_conn_event(
        tunnel_cell: Rc<RefCell<EstablishedTunnel>>,
        event_loop: &mut EventLoop,
        local_conn_event: Option<&Event>,
        remote_conn_event: Option<&Event>,
    ) {
        let mut tunnel_borrow = tunnel_cell.borrow_mut();
        let tunnel = &mut * tunnel_borrow;

        let set_status_by_event = |e: &Event, wsta: &mut ConnStatus, rsta: &mut ConnStatus| {
            if e.is_readable() { *rsta = ConnStatus::Available; }
            if e.is_writable() { *wsta = ConnStatus::Available; }
        };

        if let Some(e) = local_conn_event {
            set_status_by_event(e, &mut tunnel.local_wsta, &mut tunnel.local_rsta);
        }
        if let Some(e) = remote_conn_event {
            set_status_by_event(e, &mut tunnel.remote_wsta, &mut tunnel.remote_rsta);
        }

        tunnel.do_transfer();

        if tunnel.remote_rsta == ConnStatus::Error || tunnel.remote_wsta == ConnStatus::Error ||
            tunnel.local_rsta == ConnStatus::Error || tunnel.local_wsta == ConnStatus::Error
        {
            tunnel.crash_tunnel();
            return;
        }

        let get_interest_by_status = |wsta: &ConnStatus, rsta: &ConnStatus| {
            if *wsta == ConnStatus::Block && *rsta == ConnStatus::Block {
                Some(Interest::WRITABLE | Interest::READABLE)
            } else if *wsta == ConnStatus::Block {
                Some(Interest::WRITABLE)
            } else if *rsta == ConnStatus::Block {
                Some(Interest::READABLE)
            } else {
                None
            }
        };

        drop(tunnel);
        drop(tunnel_borrow);

        let tunnel = tunnel_cell.borrow();
        let local_interest = get_interest_by_status(&tunnel.local_wsta, &tunnel.local_rsta);
        let remote_interest = get_interest_by_status(&tunnel.remote_wsta, &tunnel.remote_rsta);
        drop(tunnel);

        if let Some(i) = local_interest {
            event_loop.reregister(Box::new(EstablishedTunnelLocalConnHandler {
                tunnel: tunnel_cell.clone(),
                interest: i,
            })).unwrap();
        }
        if let Some(i) = remote_interest {
            event_loop.reregister(Box::new(EstablishedTunnelRemoteConnHandler {
                tunnel: tunnel_cell.clone(),
                interest: i,
            })).unwrap();
        }
    }

    fn crash_tunnel(&mut self) {
        // wd_log::log_warn_ln!("Tunnel is crashing due to the unrecoverable error.");
        let r = self.local_conn.shutdown(std::net::Shutdown::Both);
        if let Err(e) = r {
            wd_log::log_warn_ln!("Fail to shutdown local conn {}", e);
        }
        let r = self.remote_conn.shutdown(std::net::Shutdown::Both);
        if let Err(e) = r {
            wd_log::log_warn_ln!("Fail to shutdown remote conn {}", e);
        }
        // TODO: unregister handler
    }

    fn do_transfer(&mut self) {
        use std::iter::zip;
        let tf_number = self.transformers.len();

        loop {
            let mut transfer_count = 0;

            // fill buffers on transmit path
            for _ in 0..8 {
                let mut xfer_count = 0;
                // read from: local_conn
                {
                    let bf = &mut self.transmit_buffers.first_mut().unwrap();
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_readable() && buf.len() == 0 && self.local_rsta == ConnStatus::Available {
                        buf.resize(buf.capacity(), 0);
                        match self.local_conn.read(buf.as_mut_slice()) {
                            Ok(0) => {
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                                self.local_rsta = ConnStatus::Shutdown;
                            }
                            Ok(s) => {
                                wd_log::log_debug_ln!("Tunnel # local conn read {}", s);
                                self.local_rsta = ConnStatus::Available;
                                buf.resize(s, 0);
                                xfer_count += s;
                            }
                            Err(ref e) if would_block(e) => {
                                buf.resize(0, 0);
                                self.local_rsta = ConnStatus::Block;
                            }
                            Err(ref e) if connection_error(e) => {
                                wd_log::log_debug_ln!("Connection Error {:?}", e);
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                                self.local_rsta = ConnStatus::Shutdown;
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Connection Error {:?}", e);
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                                self.local_rsta = ConnStatus::Error;
                            }
                        }
                    }
                }
                // read from: transformer units
                assert_eq!(self.transmit_buffers.iter().count(), tf_number+1);
                for (i, (bf, tf)) in zip(0.., zip(
                    self.transmit_buffers.iter_mut().skip(1),
                    self.transformers.iter_mut()
                )) {
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_readable() && buf.len() == 0 {
                        buf.resize(buf.capacity(), 0);
                        match tf.transmit_read(buf.as_mut_slice()) {
                            Ok(s) => {
                                wd_log::log_debug_ln!("Transformer #{} transmit_read {}", i, s);
                                buf.resize(s, 0);
                                xfer_count += s;
                            }
                            Err(TransformerUnitError::IoError(ref e)) if would_block(e) => {
                                // wd_log::log_debug_ln!("Transformer #{} transmit_read would_block", i);
                                buf.resize(0, 0);
                            }
                            Err(TransformerUnitError::ClosedError()) => {
                                wd_log::log_debug_ln!("Transformer #{} transmit_read close", i);
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Transform Error R {:?}", e);
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                            }
                        }
                    }
                }

                transfer_count += xfer_count;
                if xfer_count == 0 { break; }
            }

            // output buffers on transmit path
            for _ in 0..8 {
                let mut xfer_count = 0;
                // write into: transformer units
                for (i, (bf, tf)) in zip(0.., zip(
                    self.transmit_buffers.iter_mut().take(tf_number),
                    self.transformers.iter_mut()
                )) {
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_writable() && buf.len() > 0 {
                        match tf.transmit_write(buf.as_slice()) {
                            Ok(s) => {
                                wd_log::log_debug_ln!("Transformer #{} transmit_write {}", i, s);
                                buf.drain(0..s);
                                xfer_count += s;
                            }
                            Err(TransformerUnitError::IoError(ref e)) if would_block(e) => {
                                // wd_log::log_debug_ln!("Transformer #{} transmit_write would_block", i);
                                buf.drain(0..0);
                            }
                            Err(TransformerUnitError::ClosedError()) => {
                                wd_log::log_debug_ln!("Transformer #{} transmit_write close", i);
                                sta.remove(Interest::WRITABLE);
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Transform Error W {:?}", e);
                                sta.remove(Interest::WRITABLE);
                            }
                        }
                    }
                    if !sta.is_writable() {
                        buf.clear();
                    }
                }
                // write into: remote connection
                {
                    let bf = self.transmit_buffers.last_mut().unwrap();
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_writable() && buf.len() > 0 && self.remote_wsta == ConnStatus::Available {
                        match self.remote_conn.write(buf.as_slice()) {
                            Ok(s) => {
                                buf.drain(0..s);
                                xfer_count += s;
                                wd_log::log_debug_ln!("Tunnel # remote conn write {}", s);
                            }
                            Err(ref e) if would_block(e) => {
                                self.remote_wsta = ConnStatus::Block;
                            }
                            Err(ref e) if connection_error(e) => {
                                wd_log::log_debug_ln!("Connection Error {:?}", e);
                                sta.remove(Interest::WRITABLE);
                                self.remote_wsta = ConnStatus::Shutdown;
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Connection Error {:?}", e);
                                sta.remove(Interest::WRITABLE);
                                self.remote_wsta = ConnStatus::Error;
                            }
                        }
                    }
                    if !sta.is_writable() {
                        buf.clear();
                    }
                }

                transfer_count += xfer_count;
                if xfer_count == 0 { break; }
            }

            // fill buffers on receive path
            for _ in 0..8 {
                let mut xfer_count = 0;
                // read from: remote_conn
                {
                    let bf = &mut self.receive_buffers.last_mut().unwrap();
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_readable() && buf.len() == 0 && self.remote_rsta == ConnStatus::Available {
                        buf.resize(buf.capacity(), 0);
                        match self.remote_conn.read(buf.as_mut_slice()) {
                            Ok(0) => {
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                                self.remote_rsta = ConnStatus::Shutdown;
                            }
                            Ok(s) => {
                                buf.resize(s, 0);
                                xfer_count += s;
                                wd_log::log_debug_ln!("Tunnel # remote conn read {}", s);
                            }
                            Err(ref e) if would_block(e) => {
                                buf.resize(0, 0);
                                self.remote_rsta = ConnStatus::Block;
                            }
                            Err(ref e) if connection_error(e) => {
                                wd_log::log_debug_ln!("Connection Error {:?}", e);
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                                self.remote_rsta = ConnStatus::Shutdown;
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Connection Error {:?}", e);
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                                self.remote_rsta = ConnStatus::Error;
                            }
                        }
                    }
                }
                // read from: transformer units
                for (bf, tf) in zip(
                    self.receive_buffers.iter_mut().take(tf_number),
                    self.transformers.iter_mut()
                ) {
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_readable() && buf.len() == 0 {
                        buf.resize(buf.capacity(), 0);
                        match tf.receive_read(buf.as_mut_slice()) {
                            Ok(s) => {
                                buf.resize(s, 0);
                                xfer_count += s;
                            }
                            Err(TransformerUnitError::IoError(ref e)) if would_block(e) => {
                                buf.resize(0, 0);
                            }
                            Err(TransformerUnitError::ClosedError()) => {
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Tunnel # Transform Error RR {:?}", e);
                                buf.resize(0, 0);
                                sta.remove(Interest::READABLE);
                            }
                        }
                    }
                }

                transfer_count += xfer_count;
                if xfer_count == 0 { break; }
            }

            // output buffers on receive path
            for _ in 0..8 {
                let mut xfer_count = 0;
                // write into: transformer units
                for (bf, tf) in zip(
                    self.receive_buffers.iter_mut().skip(1),
                    self.transformers.iter_mut()
                ) {
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_writable() && buf.len() > 0 {
                        match tf.receive_write(buf.as_slice()) {
                            Ok(s) => {
                                buf.drain(0..s);
                                xfer_count += s;
                            }
                            Err(TransformerUnitError::IoError(ref e)) if would_block(e) => {
                                buf.drain(0..0);
                            }
                            Err(TransformerUnitError::ClosedError()) => {
                                sta.remove(Interest::WRITABLE);
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Tunnel # Transform Error W {:?}", e);
                                sta.remove(Interest::WRITABLE);
                            }
                        }
                    }
                    if !sta.is_writable() {
                        buf.clear();
                    }
                }
                // write into: local connection
                {
                    let bf = self.receive_buffers.first_mut().unwrap();
                    let sta = &bf.1;
                    let buf = &mut bf.0;
                    if sta.is_writable() && buf.len() > 0 && self.local_wsta == ConnStatus::Available {
                        match self.local_conn.write(buf.as_slice()) {
                            Ok(s) => {
                                buf.drain(0..s);
                                xfer_count += s;
                                wd_log::log_debug_ln!("Tunnel # local conn write {}", s);
                            }
                            Err(ref e) if would_block(e) => {
                                self.local_wsta = ConnStatus::Block;
                            }
                            Err(ref e) if connection_error(e) => {
                                wd_log::log_debug_ln!("Tunnel # Connection Error {:?}", e);
                                sta.remove(Interest::WRITABLE);
                                self.local_wsta = ConnStatus::Shutdown;
                            }
                            Err(ref e) => {
                                wd_log::log_warn_ln!("Tunnel # Connection Error {:?}", e);
                                sta.remove(Interest::WRITABLE);
                                self.local_wsta = ConnStatus::Error;
                            }
                        }
                    }
                    if !sta.is_writable() {
                        buf.clear();
                    }
                }

                transfer_count += xfer_count;
                if xfer_count == 0 { break; }
            }

            if transfer_count == 0 { break; }
        }
    }
}


struct EstablishedTunnelLocalConnHandler {
    tunnel: Rc<RefCell<EstablishedTunnel>>,
    interest: Interest,
}

impl EventHandler for EstablishedTunnelLocalConnHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.register(&mut tunnel.local_conn, tunnel.local_token, self.interest)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.reregister(&mut tunnel.local_conn, tunnel.local_token, self.interest)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_writable() && self.interest.is_writable()
            || event.is_readable() && self.interest.is_readable() {
            EstablishedTunnel::process_conn_event(self.tunnel, event_loop, Some(event), None);
        }
    }
}


struct EstablishedTunnelRemoteConnHandler {
    tunnel: Rc<RefCell<EstablishedTunnel>>,
    interest: Interest,
}

impl EventHandler for EstablishedTunnelRemoteConnHandler {
    fn register(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.register(&mut tunnel.remote_conn, tunnel.remote_token, self.interest)
    }

    fn reregister(&mut self, registry: &mut EventRegistryIntf) -> io::Result<()> {
        let tunnel = &mut * self.tunnel.borrow_mut();
        registry.reregister(&mut tunnel.remote_conn, tunnel.remote_token, self.interest)
    }

    fn handle(self: Box<Self>, event: &Event, event_loop: &mut EventLoop) {
        if event.is_writable() && self.interest.is_writable()
            || event.is_readable() && self.interest.is_readable() {
            EstablishedTunnel::process_conn_event(self.tunnel, event_loop, None, Some(event));
        }
    }
}
