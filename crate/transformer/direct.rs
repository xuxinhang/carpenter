use std::io::{Read, Write};
use crate::transformer::{TunnelTransformer, TransferResult};
use super::buffer::StreamBuffer;


pub struct TunnelDirectTransformer {
    transmit_buffer: StreamBuffer,
    receive_buffer: StreamBuffer,
}

impl TunnelDirectTransformer {
    pub fn new() -> Self {
        Self {
            transmit_buffer: StreamBuffer::new(),
            receive_buffer: StreamBuffer::new(),
        }
    }
}

impl TunnelTransformer for TunnelDirectTransformer {
    fn transmit_write(&mut self, source: &mut dyn Read) -> TransferResult {
        match self.transmit_buffer.read_from(source) {
            Ok(Some(0)) => TransferResult::Data(0),
            Ok(Some(n)) => TransferResult::Data(n),
            Ok(None) => TransferResult::End(0),
            Err(e) => TransferResult::IoError(e),
        }
    }
    fn transmit_read(&mut self, target: &mut dyn Write) -> TransferResult {
        match self.transmit_buffer.write_into(target) {
            Ok(Some(0)) => TransferResult::Data(0),
            Ok(Some(n)) => TransferResult::Data(n),
            Ok(None) => TransferResult::End(0),
            Err(e) => TransferResult::IoError(e),
        }
    }
    fn receive_write(&mut self, source: &mut dyn Read) -> TransferResult {
        match self.receive_buffer.read_from(source) {
            Ok(Some(0)) => TransferResult::Data(0),
            Ok(Some(n)) => TransferResult::Data(n),
            Ok(None) => TransferResult::End(0),
            Err(e) => TransferResult::IoError(e),
        }
    }
    fn receive_read(&mut self, target: &mut dyn Write) -> TransferResult {
        match self.receive_buffer.write_into(target) {
            Ok(Some(0)) => TransferResult::Data(0),
            Ok(Some(n)) => TransferResult::Data(n),
            Ok(None) => TransferResult::End(0),
            Err(e) => TransferResult::IoError(e),
        }
    }
}

