// use std::io::Result;
use std::collections::HashMap;


pub fn parse_http_header(chunk: &[u8]) -> Option<(usize, HashMap<String, String>)> {
    // let consume_string = |bytes: &[u8]| -> (String, &[u8]) {
    fn consume_string(bytes: &[u8]) -> (String, &[u8]) {
        let idx = bytes.iter().position(|x| *x == '\r' as u8 || *x == ' ' as u8)
            .unwrap_or(bytes.len());
        let (prefix, rest) = bytes.split_at(idx);
        (String::from_utf8(prefix.to_vec()).unwrap_or_default(), rest)
    }
    // let consume_whitespaces = |bytes: &[u8]| {
    fn consume_whitespaces(bytes: &[u8]) -> (String, &[u8]) {
        let idx = bytes.iter().position(|x|
            *x != ' ' as u8) // && *x != '\n' as u8 && *x != '\r' as u8)
            .unwrap_or(bytes.len());
        let (prefix, rest) = bytes.split_at(idx);
        (String::from_utf8(prefix.to_vec()).unwrap_or_default(), rest)
    }
    // let consume_crlf = |bytes: &[u8]| {
    fn consume_crlf(bytes: &[u8]) -> (String, &[u8]) {
        if bytes.starts_with(&['\r' as u8, '\n' as u8]) {
            (String::from("\r\n"), &bytes[2..])
        } else {
            (String::new(), &bytes[..])
        }
    }
    // let consume_field_value = |bytes: &[u8]| {
    fn consume_field_value(bytes: &[u8]) -> (String, &[u8]) {
        let idx = bytes.iter().position(|x| *x == '\r' as u8)
            .unwrap_or(bytes.len());
        let (prefix, rest) = bytes.split_at(idx);
        (String::from_utf8(prefix.to_vec()).unwrap_or_default(), rest)
    }

    let s = &chunk[..];
    let mut headers = HashMap::<String, String>::new();

    let (method, s) = consume_string(s);
    headers.insert(String::from(":method"), method);
    let (_, s) = consume_whitespaces(s);
    let (path, s) = consume_string(s);
    headers.insert(String::from(":path"), path);
    let (_, s) = consume_whitespaces(s);
    let (version, s) = consume_string(s);
    headers.insert(String::from(":version"), version);
    let (_, s) = consume_whitespaces(s);
    let (_, s) = consume_crlf(s);

    let mut ss = s;
    loop {
        let s = ss;
        let (mut key, s) = consume_string(s);
        if key.ends_with(":") {
            key.pop();
        }
        let (_, s) = consume_whitespaces(s);
        let (value, s) = consume_field_value(s);
        let (_, s) = consume_crlf(s);
        headers.insert(key, value);

        if s.starts_with("\r\n".as_bytes()) {
            let (_, s) = consume_crlf(s);
            ss = s;
            break;
        }
        if s.is_empty() {
            ss = s;
            break;
        }
        ss = s;
    }

    Some((chunk.len() - ss.len(), headers))
}

