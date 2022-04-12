use std::io::{Read, Write};
use crate::transformer::{TunnelTransformer, TransferResult};
use super::buffer::StreamBuffer;


pub struct TunnelDirectTransformer {
    transmit_buffer: StreamBuffer,
    transmit_closed: bool,
    receive_buffer: StreamBuffer,
    receive_closed: bool,
}

impl TunnelDirectTransformer {
    pub fn new() -> Self {
        Self {
            transmit_buffer: StreamBuffer::new(),
            transmit_closed: false,
            receive_buffer: StreamBuffer::new(),
            receive_closed: false,
        }
    }
}

impl TunnelTransformer for TunnelDirectTransformer {
    fn transmit_write(&mut self, source: &mut dyn Read) -> TransferResult {
        match self.transmit_buffer.read_from(source) {
            (Some(Err(e)), _) => {
                self.transmit_closed = true;
                (Err(format!("{:?}", e)), true)
            },
            (Some(Ok(n)), _) => {
                if n == 0 { self.transmit_closed = true; }
                (Ok(n), self.transmit_closed)
            },
            (None, _) => (Ok(0), self.transmit_closed),
        }
    }
    fn transmit_read(&mut self, target: &mut dyn Write) -> TransferResult {
        match self.transmit_buffer.write_into(target) {
            (Some(Err(e)), _) => (Err(format!("{:?}", e)), true), // TODO
            (Some(Ok(n)), pending) => (Ok(n), self.transmit_closed && pending == 0),
            (None, pending) => (Ok(0), self.transmit_closed && pending == 0),
        }
    }
    fn receive_write(&mut self, source: &mut dyn Read) -> TransferResult {
        match self.receive_buffer.read_from(source) {
            (Some(Err(e)), _) => (Err(format!("{:?}", e)), true),
            (Some(Ok(n)), _) => {
                if n == 0 { self.receive_closed = true; }
                (Ok(n), self.receive_closed)
            },
            (None, _) => (Ok(0), self.receive_closed),
        }
    }
    fn receive_read(&mut self, target: &mut dyn Write) -> TransferResult {
        match self.receive_buffer.write_into(target) {
            (Some(Err(e)), _) => (Err(format!("{:?}", e)), true),
            (Some(Ok(n)), pending) => (Ok(n), self.receive_closed && pending == 0),
            (None, pending) => (Ok(0), self.receive_closed && pending == 0),
        }
    }
}

