use std::io::{Read, Write};

pub type TransferResult = (std::result::Result<usize, String>, bool);

pub trait TunnelTransformer {
    fn transmit_write(&mut self, source: &mut dyn Read) -> TransferResult;
    fn transmit_read(&mut self, target: &mut dyn Write) -> TransferResult;
    fn receive_write(&mut self, source: &mut dyn Read) -> TransferResult;
    fn receive_read(&mut self, target: &mut dyn Write) -> TransferResult;
}

pub trait Transformer {
    fn transmit_write(&mut self, buf: &[u8]) -> TransformerResult;
    fn transmit_writable(&self) -> TransformerPortState;
    fn transmit_read(&mut self, buf: &mut [u8]) -> TransformerResult;
    fn transmit_readable(&self) -> TransformerPortState;
    fn receive_write(&mut self, buf: &[u8]) -> TransformerResult;
    fn receive_writable(&self) -> TransformerPortState;
    fn receive_read(&mut self, buf: &mut [u8]) -> TransformerResult;
    fn receive_readable(&self) -> TransformerPortState;
}

#[derive(Debug)]
pub enum TransformerResult {
    Ok(usize),
    IoError(std::io::Error),
    ProtocolError(rustls::Error),
    CustomError(&'static str, Option<String>),
}

pub enum TransformerPortState {
    Open(isize),
    Closed,
}


// enum HostName {
//     Ipv4(std::net::Ipv4Addr),
//     Ipv6(std::net::Ipv6Addr),
//     DomainName(String),
// }
