use std::io::{self, Read, Write};
use std::collections::VecDeque;


const STREAM_BUFFER_CAPACITY: usize = 4 * 1024 * 1024;
const STREAM_BUFFER_BRUST_SIZE: usize = 16 * 1024;

pub struct StreamBuffer {
    buf: VecDeque<u8>,
    max_size: usize,
}

impl StreamBuffer {
    pub fn new() -> Self {
        Self {
            buf: VecDeque::with_capacity(STREAM_BUFFER_BRUST_SIZE),
            max_size: STREAM_BUFFER_CAPACITY,
        }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: VecDeque::with_capacity(cap),
            max_size: cap,
        }
    }

    pub fn readable_size(&self) -> usize {
        self.buf.len()
    }

    pub fn writable_size(&self) -> usize {
        self.max_size - self.buf.len()
    }
}

impl Write for StreamBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.writable_size() == 0 {
            return Ok(0);
        }

        let s = std::cmp::min(self.writable_size(), buf.len());
        // TODO: any method with better performance
        self.buf.extend(buf.iter().take(s));
        Ok(s)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for StreamBuffer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.readable_size() == 0 {
            return Ok(0);
        }

        // let (fst_slice, snd_slice) = self.buf.as_slices();
        // if fst_slice.len() < snd_slice.len() * 8 {
        //     self.buf.make_contiguous();
        // }
        // let (read_slice, _) = self.buf.as_slices();
        self.buf.make_contiguous();
        let (read_slice, _) = self.buf.as_slices();

        let s = std::cmp::min(read_slice.len(), buf.len());
        buf[..s].copy_from_slice(&read_slice[..s]);
        self.buf.drain(..s);
        Ok(s)
    }
}
