use std::io::{Read, Write};

pub type TransferResult = (Result<usize, String>, bool);

pub trait TunnelTransformer {
    fn transmit_write(&mut self, source: &mut dyn Read) -> TransferResult;
    fn transmit_read(&mut self, target: &mut dyn Write) -> TransferResult;
    fn receive_write(&mut self, source: &mut dyn Read) -> TransferResult;
    fn receive_read(&mut self, target: &mut dyn Write) -> TransferResult;
}
