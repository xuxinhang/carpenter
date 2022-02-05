use std::io;
use std::io::{Read, Write};

pub trait TunnelTransformer {
    fn transmit_write(&mut self, source: &mut impl Read) -> io::Result<Option<usize>>;
    fn transmit_read(&mut self, target: &mut impl Write) -> io::Result<Option<usize>>;
    fn receive_write(&mut self, source: &mut impl Read) -> io::Result<Option<usize>>;
    fn receive_read(&mut self, target: &mut impl Write) -> io::Result<Option<usize>>;
}

