pub mod tls_struct;

use std::str::FromStr;
use httparse;
use crate::common::{HostAddress, HostParseError};

pub fn check_http_message_header_ending(bytes: &[u8]) -> bool {
    bytes.len() >= 4 &&
    bytes[bytes.len() - 4] == b'\r' && bytes[bytes.len() - 3] == b'\n' &&
    bytes[bytes.len() - 2] == b'\r' && bytes[bytes.len() - 1] == b'\n'
}


pub fn find_http_message_header_ending(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 4 {
        return None;
    }

    for i in 0..(bytes.len() - 3) {
        if bytes[i] == b'\r' && bytes[i + 1] == b'\n' &&
           bytes[i + 2] == b'\r' && bytes[i + 3] == b'\n' {
            return Some(i + 4);
        }
    }

    None
}


pub(crate) struct HttpRequestMessage {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, Vec<u8>)>,
}

impl HttpRequestMessage {
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), httparse::Error> {
        let count = bytes.iter().filter(|&&c| c == b'\n').count();
        let mut headers = vec![httparse::EMPTY_HEADER; count];
        let mut req = httparse::Request::new(&mut headers);
        let status = req.parse(bytes)?;
        if status.is_partial() {
            return Err(httparse::Error::NewLine);
        }
        Ok((
            Self {
                method: req.method.unwrap().to_string().to_uppercase(),
                path: req.path.unwrap().to_string(),
                headers: headers.iter().map(|h| (h.name.to_string(), h.value.to_vec())).collect(),
            },
            status.unwrap(),
        ))
    }

    pub fn is_tunnel_mode(&self) -> bool {
        self.method == "CONNECT"
    }

    pub fn get_host_addr(&self) -> Result<HostAddress, HostParseError> {
        if self.is_tunnel_mode() {
            HostAddress::from_str(self.path.as_str())
        } else {
            let u = url::Url::parse(&self.path).map_err(|_e| HostParseError())?;
            Ok(HostAddress(
                u.host_str().ok_or(HostParseError())?.parse().map_err(|_e| HostParseError())?,
                u.port().ok_or(HostParseError())?,
            ))
        }
    }
}
