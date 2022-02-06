use std::io;
use std::io::{Read, Write};

pub trait TunnelTransformer {
    fn transmit_write(&mut self, source: &mut impl Read) -> TransferResult;
    fn transmit_read(&mut self, target: &mut impl Write) -> TransferResult;
    fn receive_write(&mut self, source: &mut impl Read) -> TransferResult;
    fn receive_read(&mut self, target: &mut impl Write) -> TransferResult;
}


pub enum TransferResult {
    End(usize),
    Data(usize),
    Error,
}
