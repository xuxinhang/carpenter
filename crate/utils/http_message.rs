use std::collections::HashMap;

pub fn parse_http_header(chunk: &[u8]) -> Option<(usize, HashMap<String, String>)> {
    use std::str;
    use std::char::from_u32;

	fn consume_field_name(bytes: &[u8]) -> Option<(String, &[u8])> {
        let i = bytes.iter()
            .position(|c| from_u32((*c).into()).unwrap().is_whitespace() || *c == ':' as u8)
            .unwrap_or(bytes.len());
        let (x, y) = bytes.split_at(i);
        Some((str::from_utf8(x).ok()?.to_string(), y))
	}

    fn consume_field_value(bytes: &[u8]) -> Option<(String, &[u8])> {
        let i = bytes.iter().position(|c| *c == '\r' as u8).unwrap_or(bytes.len());
        let (x, y) = bytes.split_at(i);
        Some((str::from_utf8(x).ok()?.to_string(), y))
    }

    fn consume_string(bytes: &[u8]) -> Option<(String, &[u8])> {
        let i = bytes.iter().position(|c| *c == '\r' as u8 || *c == ' ' as u8)
            .unwrap_or(bytes.len());
        let (x, y) = bytes.split_at(i);
        Some((str::from_utf8(x).ok()?.to_string(), y))
    }

    fn consume_spaces(bytes: &[u8]) -> Option<(String, &[u8])> {
        let i = bytes.iter().position(|c| *c != ' ' as u8).unwrap_or(bytes.len());
        let (x, y) = bytes.split_at(i);
        Some((str::from_utf8(x).ok()?.to_string(), y))
    }

    fn consume_crlf(bytes: &[u8]) -> Option<(String, &[u8])> {
        if bytes.starts_with(&['\r' as u8, '\n' as u8]) {
            Some((String::from("\r\n"), &bytes[2..]))
        } else {
            None
        }
    }

    fn consume_colon(bytes: &[u8]) -> Option<(String, &[u8])> {
        if *(bytes.first()?) == ':' as u8 {
            Some((":".to_string(), &bytes[1..]))
        } else {
            None
        }
    }

    let s = &chunk[..];
    let mut header_map = HashMap::new();

    let (x, s) = consume_string(s)?;
    header_map.insert(String::from(":method"), x);

    let (_, s) = consume_spaces(s)?;
    let (x, s) = consume_string(s)?;
    header_map.insert(String::from(":path"), x);

    let (_, s) = consume_spaces(s)?;
    let (x, s) = consume_string(s)?;
    header_map.insert(String::from(":version"), x);

    let (_, s) = consume_spaces(s)?;
    let (_, s) = consume_crlf(s)?;

    let mut ss = s;
    loop {
        let s = ss;
        if s.starts_with("\r\n".as_bytes()) {
            let (_, s) = consume_crlf(s)?;
            ss = s;
            break;
        }

        let (k, s) = consume_field_name(s)?;
        let (_, s) = consume_colon(s)?;
        let (_, s) = consume_spaces(s)?;
        let (v, s) = consume_field_value(s)?;
        let (_, s) = consume_crlf(s)?;
        header_map.insert(k, v);

        ss = s;
    }

    Some((chunk.len()-ss.len(), header_map))
}
