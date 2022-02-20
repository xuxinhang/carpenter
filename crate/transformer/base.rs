use std::io::{Read, Write};


pub trait TunnelTransformer {
    fn transmit_write(&mut self, source: &mut dyn Read) -> TransferResult;
    fn transmit_read(&mut self, target: &mut dyn Write) -> TransferResult;
    fn receive_write(&mut self, source: &mut dyn Read) -> TransferResult;
    fn receive_read(&mut self, target: &mut dyn Write) -> TransferResult;
}


pub enum TransferResult {
    End(usize),
    Data(usize),
    IoError(std::io::Error),
    TlsError(rustls::Error),
}
