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

    pub fn wants_read(&self) -> usize {
        self.max_size - self.buf.len()
    }

    pub fn wants_write(&self) -> usize {
        self.buf.len()
    }

    pub fn read_from(&mut self, s: &mut dyn Read) -> (Option<io::Result<usize>>, usize) {
        if self.wants_read() == 0 {
            (None, 0)
        } else {
            // TODO: it's better to read into VecDeque memory directly
            let mut buf = vec![0; self.wants_read()];
            let result = s.read(&mut buf);
            match result {
                Ok(n) => self.buf.extend(buf.iter().take(n)),
                _ => {},
            }
            (Some(result), self.wants_read())
        }
    }

    pub fn write_into(&mut self, t: &mut dyn Write) -> (Option<io::Result<usize>>, usize) {
        if self.wants_write() == 0 {
            (None, 0)
        } else {
            self.buf.make_contiguous(); // TODO
            let (fst_slice, _snd_slice) = self.buf.as_slices();
            let mut size_accu = 0;
            let io_result = t.write(fst_slice);
            match io_result {
                Ok(size) => {
                    size_accu += size;
                    self.buf.drain(..size_accu);
                },
                _ => {},
            }
            (Some(io_result), self.wants_write())
        }
    }
}


