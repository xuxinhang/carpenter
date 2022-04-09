use std::io::{self, Read, Write};
use std::collections::VecDeque;


const STREAM_BUFFER_CAPACITY: usize = 4 * 1024 * 1024;
const STREAM_BUFFER_BRUST_SIZE: usize = 1 * 1024 * 1024;

pub struct StreamBuffer {
    buf: VecDeque<u8>,
    state: i8, // 0 = running, 1 = eof, -1 = io_err
    max_size: usize,
}

impl StreamBuffer {
    pub fn new() -> Self {
        Self {
            buf: VecDeque::with_capacity(STREAM_BUFFER_BRUST_SIZE * 2),
            state: 0,
            max_size: STREAM_BUFFER_CAPACITY,
        }
    }

    fn wants_read(&self) -> usize {
        self.max_size - self.buf.len()
    }

    fn wants_write(&self) -> usize {
        self.buf.len()
    }

    pub fn set_state(&mut self, s: i8) {
        self.state = s;
    }

    pub fn get_state(&self) -> i8 {
        self.state
    }

    pub fn read_from(&mut self, s: &mut dyn Read) -> io::Result<Option<usize>> {
        if self.wants_read() == 0 {
            return Ok(Some(0));
        }

        // TODO: it's better to read into VecDeque memory directly
        let mut buf = vec![0; self.wants_read()];
        match s.read(&mut buf) {
            Err(e) => {
                self.set_state(-1);
                return Err(e);
            }
            Ok(0) => {
                self.set_state(1);
                return Ok(None);
            }
            Ok(n) => {
                self.set_state(0);
                self.buf.extend(buf.iter().take(n));
                return Ok(Some(n));
            }
        }
    }

    pub fn write_into(&mut self, t: &mut dyn Write) -> io::Result<Option<usize>> {
        if self.wants_write() == 0 {
            if self.get_state() != 0 {
                return Ok(None);
            } else {
                return Ok(Some(0));
            }
        }

        self.buf.make_contiguous(); // TODO
        let (fst_slice, _snd_slice) = self.buf.as_slices();
        let mut size_accu = 0;

        match t.write(fst_slice) {
            Err(e) => {
                return Err(e);
            }
            Ok(size) => {
                size_accu += size;
                self.buf.drain(..size_accu);
                return Ok(Some(size_accu));
            }
        }
    }
}


