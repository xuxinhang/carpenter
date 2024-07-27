
#[derive(Debug)]
pub enum HttpMessageParseError {
    SyntaxError,
}

#[derive(PartialEq)]
pub enum HttpMethod { CONNECT, Other(String) }

pub struct HttpRequestMessage {
    pub target: HttpRequestTarget,
    pub method: HttpMethod,
    pub version: u8,
    pub fields: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub enum HttpRequestTarget {
    Origin(String), // absolute-path
    Absolute(String), // absolute-uri
    Authority(String),
    Asterisk,
    Other(String),
}

impl TryFrom<&[u8]> for HttpRequestMessage {
    type Error = HttpMessageParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        match consume_request_message(bytes) {
            Some((body, mut msg)) => {
                msg.body.extend_from_slice(body);
                Ok(msg)
            },
            None => Err(HttpMessageParseError::SyntaxError),
        }
    }
}


struct HttpResponseMessage {
    pub version: u8,
    pub code: u16,
    pub reason: String,
    pub fields: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl TryFrom<&[u8]> for HttpResponseMessage {
    type Error = HttpMessageParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        match consume_response_message(bytes) {
            Some((body, mut msg)) => {
                msg.body.extend_from_slice(body);
                Ok(msg)
            },
            None => Err(HttpMessageParseError::SyntaxError),
        }
    }
}



macro_rules! consume_str {
    ($s:expr, $p:expr) => {
        if ($s).starts_with($p) { Some(&$s[($p).len()..]) } else { None }
    };
}



fn consume_space(s: &str) -> Option<&str> {
    consume_str!(s, " ")
}

fn consume_crlf(s: &str) -> Option<&str> {
    consume_str!(s, "\r\n")
}

fn consume_colon(s: &str) -> Option<&str> {
    consume_str!(s, ":")
}

fn consume_ows<'o>(s: &'o str) -> Option<(&'o str, &'o str)> {
    let i = s.find(|x| !(x == ' ' || x == '\t')).unwrap_or(s.len());
    Some((&s[i..], &s[..i]))
}

fn consume_rws<'o>(s: &'o str) -> Option<(&'o str, &'o str)> {
    let i = s.find(|x| !(x == ' ' || x == '\t')).unwrap_or(s.len());
    if i == 0 { None } else { Some((&s[i..], &s[..i])) }
}

fn is_tchar (x: char) -> bool {
    "!#$%&'*+-.^_`|~".find(x).is_some() || x.is_ascii_alphanumeric()
}
fn is_obs_text (x: char) -> bool { '\u{80}' <= x && x <= '\u{FF}' }
fn is_vchar (x: char) -> bool { '\u{21}' <= x && x <= '\u{7E}' }

fn consume_eof(s: &str) -> Option<&str> {
    if s.is_empty() { Some(s) } else { None }
}


fn consume_digit (s: &str) -> Option<(&str, u8)> {
    s.chars().nth(0).map_or(None, |x|
        if x.is_ascii_digit() {
            Some((&s[1..], u8::try_from(x).unwrap()-b'0'))
        } else {
            None
        })
}

fn consume_token(s: &str) -> Option<(&str, &str)> {
    match s.find(|x| !is_tchar(x)).unwrap_or(s.len()) {
        0 => None,
        i => Some((&s[i..], &s[..i])),
    }
}

fn consume_http_version(s: &str) -> Option<(&str, u8)> {
    fn consume_http_name_slash (ss: &str) -> Option<&str> { consume_str!(ss, "HTTP/") }
    fn consume_dot (ss: &str) -> Option<&str> { consume_str!(ss, ".") }
    let s = consume_http_name_slash(s)?;
    let (s, d1) = consume_digit(s)?;
    let s = consume_dot(s)?;
    let (s, d2) = consume_digit(s)?;
    Some((s, 10*(d1)+d2))
}

fn consume_request_line(s: &str) -> Option<(&str, HttpMethod, HttpRequestTarget, u8)> {
    let consume_method = |s| {
        let (s, t) = consume_token(s)?;
        Some((
            s,
            match t.to_ascii_uppercase().as_str() {
                "CONNECT" => HttpMethod::CONNECT,
                _ => HttpMethod::Other(t.to_string()),
            }
        ))
    };
    fn consume_target (s: &str) -> Option<(&str, HttpRequestTarget)> {
        match s.find(|x: char| {
            !("-_~!*'();:@&=+$,/?#[].".find(x).is_some() || x.is_ascii_alphanumeric())
        }).unwrap_or(s.len()) {
            0 => None,
            i => Some((&s[i..], match &s[..i] {
                "*" => HttpRequestTarget::Asterisk,
                _x => HttpRequestTarget::Other(String::from(&s[..i])),
            })),
        }
    }


    let (s, method) = consume_method(s)?;
    let s = consume_space(s)?;
    let (s, target) = consume_target(s)?;
    let s = consume_space(s)?;
    println!("{:?}", s);
    let (s, version) = consume_http_version(s)?;
    let s = consume_crlf(s)?;
    Some((s, method, target, version))
}

fn consume_response_line(s: &str) -> Option<(&str, u8, u16, String)> {
    fn consume_status_code(s: &str) -> Option<(&str, u16)> {
        let (s, d1) = consume_digit(s)?;
        let (s, d2) = consume_digit(s)?;
        let (s, d3) = consume_digit(s)?;
        Some((s, (d1 as u16)*100 + (d2 as u16)*10 + (d3 as u16)*1))
    }

    fn consume_reason_phrase(s: &str) -> Option<(&str, String)> {
        let f = |x|
            !(x == '\t' || x == ' ' || is_vchar(x) || is_obs_text(x));
        s.find(f).map_or(Some(("", s.to_string())),
                         |i| Some((&s[i..], s[..i].to_string())))
    }

    let (s, ver) = consume_http_version(s)?;
    let s = consume_space(s)?;
    let (s, code) = consume_status_code(s)?;
    let s = consume_space(s)?;
    let (s, rea) = consume_reason_phrase(s)?;
    let s = consume_crlf(s)?;
    Some((s, ver, code, rea))
}

fn consume_header_field(s: &str) -> Option<(&str, String, String)> {
    fn consume_field_name (s: &str) -> Option<(&str, &str)> {
        let (s, t) = consume_token(s)?;
        Some((s, t))
    }

    fn is_field_vchar (x: char) -> bool { is_vchar(x) || is_obs_text(x) }

    // field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
    // field-value = *( field-content / obs-fold )
    // field-vchar = VCHAR / obs-text

    fn consume_field_vchar (s: &str) -> Option<(&str, char)> {
        let x = s.chars().next()?;
        if is_field_vchar(x) { Some((&s[1..], x)) } else { None }
    }

    fn consume_field_content (ss: &str) -> Option<(&str, &str)> {
        let (s, _x1) = consume_field_vchar(ss)?;
        if let Some((s, _x2)) = consume_rws(s) {
            let (s, _x3) = consume_field_vchar(s)?;
            Some((s, &ss[..(ss.len()-s.len())]))
        } else {
            Some((s, &ss[..(ss.len()-s.len())]))
        }
    }

    fn consume_obs_fold (ss: &str) -> Option<(&str, &str)> {
        let s = consume_crlf(ss)?;
        let (s, _) = consume_rws(s)?;
        Some((s, &ss[..(ss.len()-s.len())]))
    }

    fn consume_field_value(ss: &str) -> Option<(&str, &str)> {
        let mut s = ss;
        loop {
            match consume_field_content(s).or(consume_obs_fold(s)) {
                Some((s_next, _)) => s = s_next,
                None => break,
            }
        }
        Some((s, &ss[..(ss.len()-s.len())]))
    }

    let (s, name) = consume_field_name(s)?;
    let s = consume_colon(s)?;
    let (s, _) = consume_ows(s)?;
    let (s, value) = consume_field_value(s)?;
    let (s, _) = consume_ows(s)?;
    Some((s, name.to_string(), value.to_string()))
}

fn get_header_length(bytes: &[u8]) -> Option<usize> {
    const WINDOW: &[u8;4] = b"\r\n\r\n";

    let mut w = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if w == WINDOW.len() {
            return Some(i);
        }
        w = if b == WINDOW[w] { w + 1 } else { 0 };
    }

    if w == WINDOW.len() {
        return Some(bytes.len());
    }

    None
}

fn consume_request_message(b: &[u8]) -> Option<(&[u8], HttpRequestMessage)> {
    let header_length = get_header_length(b)?;
    let s = std::str::from_utf8(&b[..header_length]).ok()?;
    let (s, method, target, version) = consume_request_line(s)?;

    let mut fields = Vec::new();
    let mut s = s;
    loop {
        s = if let Some((s, name, value)) = consume_header_field(s) {
            let s = consume_crlf(s)?;
            fields.push((name, value));
            s
        } else {
            break;
        }
    }

    let s = consume_crlf(s)?;
    let _ = consume_eof(s)?;

    Some((
        &b[header_length..],
        HttpRequestMessage { method, target, version, fields, body: Vec::new() }
    ))
}

fn consume_response_message(b: &[u8]) -> Option<(&[u8], HttpResponseMessage)> {
    let header_length = get_header_length(b)?;
    let s = std::str::from_utf8(&b[..header_length]).ok()?;
    let (s, version, code, reason) = consume_response_line(s)?;

    let mut fields = Vec::new();
    let mut s = s;
    loop {
        s = if let Some((s, name, value)) = consume_header_field(s) {
            let s = consume_crlf(s)?;
            fields.push((name, value));
            s
        } else {
            break;
        }
    }

    let s = consume_crlf(s)?;
    let _ = consume_eof(s)?;

    Some((
        &b[header_length..],
        HttpResponseMessage { version, code, reason, fields, body: Vec::new() }
    ))
}

/*
fn consume_authority (s: &str) -> Option<(s, String, String, u16)> {
    consum
}


fn consume_userinfo (s: &str) -> Option<String> {
    // TODO:
    // pct-encoded = "%" HEXDIG HEXDIG
    // unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
    // sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
    let i = s.find(|x| !("!$&'()*+,;=".find(x).is_some()
        || x == '%' || x == ':'
        || '0' <= x && x <= '9' || 'a' <= x && x <= 'z' || 'A' <= x && x <= 'Z'));
    Some((&s[i..], &s[..i].to_string()))
}

fn consume_hier_path(s: &str) -> Option<> {

}
*/
