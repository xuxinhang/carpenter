use std::io;
use std::io::{Read, Write};
use crate::transformer::{TunnelTransformer, TransferResult};


struct TunnelPacketBuffer {
    buf: Vec<Vec<u8>>,
}

impl TunnelPacketBuffer {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    // fn push_bytes(&mut self, bytes: &[u8]) -> usize {
    //     let mut accu_size = 0;
    //     if self.buf.len() <= 64 {
    //         let b = bytes.to_vec();
    //         let read_size = b.len();
    //         accu_size += read_size;
    //         self.buf.push(b);
    //     }
    //     accu_size
    // }

    fn read_from(&mut self, sock: &mut impl Read) -> io::Result<Option<usize>> {
        let mut accu_size = 0;
        while self.buf.len() <= 64 {
            let mut b = vec![0; 4096];
            let read_size = sock.read(&mut b)?;
            accu_size += read_size;
            let short_packet = read_size < 4096;
            if short_packet {
                b.truncate(read_size);
            }
            self.buf.push(b);
            if short_packet {
                break;
            }
            break;
        }
        Ok(Some(accu_size))
    }

    fn write_into(&mut self, sock: &mut impl Write) -> io::Result<Option<usize>> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        let mut accu_size = 0;
        while !self.buf.is_empty() {
            let b = self.buf.remove(0);
            let write_size = sock.write(&b)?;
            accu_size += write_size;
            break;
        }
        Ok(Some(accu_size))
    }
}


pub struct TunnelDirectTransformer {
    transmit_buffer: TunnelPacketBuffer,
    receive_buffer: TunnelPacketBuffer,
}

impl TunnelDirectTransformer {
    pub fn new() -> Self {
        Self {
            transmit_buffer: TunnelPacketBuffer::new(),
            receive_buffer: TunnelPacketBuffer::new(),
        }
    }
}

impl TunnelTransformer for TunnelDirectTransformer {
    fn transmit_write(&mut self, source: &mut impl Read) -> TransferResult {
        match self.transmit_buffer.read_from(source) {
            Ok(Some(0)) => TransferResult::End(0),
            Ok(Some(n)) => TransferResult::Data(n),
            Ok(None) => TransferResult::Data(0),
            Err(e) => TransferResult::IoError(e),
        }
    }
    fn transmit_read(&mut self, target: &mut impl Write) -> TransferResult {
        match self.transmit_buffer.write_into(target) {
            Ok(Some(0)) => TransferResult::End(0),
            Ok(Some(n)) => TransferResult::Data(n),
            Ok(None) => TransferResult::Data(0),
            Err(e) => TransferResult::IoError(e),
        }
    }
    fn receive_write(&mut self, source: &mut impl Read) -> TransferResult {
        match self.receive_buffer.read_from(source) {
            Ok(Some(0)) => TransferResult::End(0),
            Ok(Some(n)) => TransferResult::Data(n),
            Ok(None) => TransferResult::Data(0),
            Err(e) => TransferResult::IoError(e),
        }
    }
    fn receive_read(&mut self, target: &mut impl Write) -> TransferResult {
        match self.receive_buffer.write_into(target) {
            Ok(Some(0)) => TransferResult::End(0),
            Ok(Some(n)) => TransferResult::Data(n),
            Ok(None) => TransferResult::Data(0),
            Err(e) => TransferResult::IoError(e),
        }
    }
}

