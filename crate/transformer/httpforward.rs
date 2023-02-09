use std::str::FromStr;
use std::io::{Read, Write};
use std::collections::{VecDeque};
use super::{Transformer, TransformerPortState, TransformerResult};
use super::{TransformerUnit, TransformerUnitResult, TransformerUnitError};
use super::streambuffer::StreamBuffer;
use crate::common::{HostAddr};


const HTTP_FORWARD_SCAN_POS_FIRST: u8 = 1;
const HTTP_FORWARD_SCAN_POS_HEADER: u8 = 2;
const HTTP_FORWARD_SCAN_POS_BODY: u8 = 3;

pub struct HttpForwardTransformer {
    transmit_buf: StreamBuffer,
    receive_buf: StreamBuffer,
    scan_pos: u8,
    body_len_remained: usize,
    process_buffer: VecDeque<u8>,
    _expected_host: HostAddr,
    transmit_closed: bool,
    receive_closed: bool,
}

impl HttpForwardTransformer {
    pub fn new(host: HostAddr) -> Self {
        Self {
            transmit_buf: StreamBuffer::new(),
            receive_buf: StreamBuffer::new(),
            scan_pos: HTTP_FORWARD_SCAN_POS_FIRST,
            body_len_remained: 0,
            process_buffer: VecDeque::with_capacity(32 * 1024),
            _expected_host: host,
            transmit_closed: false,
            receive_closed: false,
        }
    }

    fn process_message(&mut self) -> TransformerResult {
        let mut byte_count = 0;

        loop {
            match self.scan_pos {
                HTTP_FORWARD_SCAN_POS_FIRST => {
                    let r = find_line(&self.process_buffer);
                    if r.is_none() {
                        break;
                    }
                    let line_len = r.unwrap();
                    if line_len > self.transmit_buf.writable_size() {
                        break;
                    }

                    let mut text: String = self.process_buffer
                        .iter().take(line_len).map(|x| *x as char).collect();

                    let uri_l = (&text[0..]).find("http://");
                    if uri_l.is_none() {
                        return TransformerResult::CustomError("Invalid http path secheme", None);
                    }
                    let uri_l = uri_l.unwrap();
                    let uri_m = uri_l + 7;

                    let uri_r = (&text[uri_m..]).find('/').and_then(|x| Some(x + uri_m));
                    if uri_r.is_none() {
                        return TransformerResult::CustomError("Invalid http path suffix", None);
                    }
                    let uri_r = uri_r.unwrap();
                    let _host = HostAddr::from_str(&text[uri_m..uri_r]).ok();

                    text.drain(uri_l..uri_r);
                    let byte_slice = text.as_bytes();
                    self.transmit_buf.write(byte_slice).unwrap();
                    self.process_buffer.drain(..line_len);

                    byte_count += line_len;
                    self.scan_pos = HTTP_FORWARD_SCAN_POS_HEADER;
                    continue;
                }
                HTTP_FORWARD_SCAN_POS_HEADER => {
                    let r = find_line(&self.process_buffer);
                    if r.is_none() {
                        break;
                    }
                    let line_len = r.unwrap();
                    if line_len > self.transmit_buf.writable_size() {
                        break;
                    }

                    if line_len == 2 {
                        let u: Vec<u8> = self.process_buffer.drain(..line_len).collect();
                        self.transmit_buf.write(u.as_slice()).unwrap();
                        self.scan_pos = HTTP_FORWARD_SCAN_POS_BODY;
                        byte_count += line_len;
                        continue;
                    }

                    let text: String = self.process_buffer.iter().take(line_len).map(|x| *x as char).collect();
                    if let Some(colon_pos) = text.find(':') {
                        let field_name = &text[..colon_pos].trim();
                        let field_value = &text[(colon_pos + 1)..].trim();

                        if field_name == &"Content-Length" {
                            match field_value.parse() {
                                Err(_) => return TransformerResult::CustomError(
                                    "Invalid http header 'Content-Length'", None),
                                Ok(n) => self.body_len_remained = n,
                            }
                        }
                    }

                    let byte_slice = text.as_bytes();
                    self.transmit_buf.write(byte_slice).unwrap();
                    self.process_buffer.drain(..line_len);

                    byte_count += line_len;
                    continue;
                }
                HTTP_FORWARD_SCAN_POS_BODY => {
                    if self.body_len_remained == 0 {
                        self.scan_pos = HTTP_FORWARD_SCAN_POS_FIRST;
                        continue;
                    }

                    let (u, _) = self.process_buffer.as_slices();
                    if u.len() == 0 || self.transmit_buf.writable_size() == 0  {
                        break;
                    }
                    let s = self.transmit_buf.write(u).unwrap();
                    self.body_len_remained -= s;
                    self.process_buffer.drain(..s);
                    byte_count += s;
                    continue;
                }
                _ => unreachable!(),
            }
        }

        TransformerResult::Ok(byte_count)
    }
}


fn find_line(buf: &VecDeque<u8>) -> Option<usize> {
    if buf.len() < 2 {
        return None;
    }
    let crlf_pos = buf.iter().skip(0).zip(buf.iter().skip(1))
        .position(|(a, b)| (*a as char, *b as char) == ('\r', '\n'));
    let line_len = crlf_pos.and_then(|x| Some(x + 2));
    line_len
}


impl Transformer for HttpForwardTransformer {
    /* transmit tube */

    fn transmit_writable(&self) -> TransformerPortState {
        TransformerPortState::Open(self.transmit_buf.writable_size().try_into().unwrap())
    }

    fn transmit_write(&mut self, buf: &[u8]) -> TransformerResult {
        self.process_buffer.extend(buf.iter().take(self.transmit_buf.writable_size()));
        self.process_message()
    }

    fn transmit_readable(&self) -> TransformerPortState {
        TransformerPortState::Open(self.transmit_buf.readable_size().try_into().unwrap())
    }

    fn transmit_read(&mut self, buf: &mut [u8]) -> TransformerResult {
        TransformerResult::Ok(self.transmit_buf.read(buf).unwrap())
    }

    /* receive tube */

    fn receive_writable(&self) -> TransformerPortState {
        TransformerPortState::Open(self.receive_buf.writable_size().try_into().unwrap())
    }

    fn receive_write(&mut self, buf: &[u8]) -> TransformerResult {
        TransformerResult::Ok(self.receive_buf.write(buf).unwrap())
    }

    fn receive_readable(&self) -> TransformerPortState {
        TransformerPortState::Open(self.receive_buf.readable_size().try_into().unwrap())
    }

    fn receive_read(&mut self, buf: &mut [u8]) -> TransformerResult {
        TransformerResult::Ok(self.receive_buf.read(buf).unwrap())
    }
}


impl TransformerUnit for HttpForwardTransformer {
    fn transmit_write(&mut self, buf: &[u8]) -> TransformerUnitResult {
        if self.transmit_closed {
            return Err(TransformerUnitError::ClosedError());
        }
        self.process_buffer.extend(buf.iter().take(self.transmit_buf.writable_size()));
        match self.process_message() {
            TransformerResult::Ok(s) => Ok(s),
            TransformerResult::IoError(e) => Err(TransformerUnitError::IoError(e)),
            TransformerResult::ProtocolError(e) => Err(TransformerUnitError::TlsError(e)),
            TransformerResult::CustomError(a, b) => Err(TransformerUnitError::CustomError(a, b)),
        }
    }

    fn transmit_read(&mut self, buf: &mut [u8]) -> TransformerUnitResult {
        match self.transmit_buf.read(buf) {
            Ok(0) => {
                if self.transmit_closed && buf.len() > 0 {
                    return Err(TransformerUnitError::ClosedError());
                } else {
                    return Ok(0);
                }
            }
            Ok(s) => {
                return Ok(s);
            }
            Err(e) => {
                return Err(TransformerUnitError::IoError(e));
            }
        }
    }

    fn transmit_end(&mut self) -> TransformerUnitResult {
        self.transmit_closed = true;
        return Ok(0);
    }

    fn receive_write(&mut self, buf: &[u8]) -> TransformerUnitResult {
        if self.receive_closed {
            return Err(TransformerUnitError::ClosedError());
        }
        return Ok(self.receive_buf.write(buf).unwrap());
    }

    fn receive_read(&mut self, buf: &mut [u8]) -> TransformerUnitResult {
        match self.receive_buf.read(buf) {
            Ok(0) => {
                if self.receive_closed && buf.len() > 0 {
                    return Err(TransformerUnitError::ClosedError());
                } else {
                    return Ok(0);
                }
            }
            Ok(s) => {
                return Ok(s);
            }
            Err(e) => {
                return Err(TransformerUnitError::IoError(e));
            }
        }
    }

    fn receive_end(&mut self) -> TransformerUnitResult {
        self.receive_closed = true;
        return Ok(0);
    }
}
