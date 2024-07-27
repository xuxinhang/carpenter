use std::str::{FromStr};
use crate::credential::Credential;


#[derive(Debug)]
pub enum HttpAuthError {
    UnexpectedMessageFormat,
    InvalidParameterValue,
    UnsupportedScheme,
    UnsupportedDigestAlgorithm,
    UnexpectedMessageField,
    InvalidIdentification,
    Other(u8),
}

/*
enum HttpAuthenticationDigestAlgorithm { MD5, SHA256 }

impl ToString for HttpAuthenticationDigestAlgorithm {
    pub fn to_string(&self) -> String {
        match self {
            Self::MD5 => "MD5".into(),
            Self::SHA256 => "SHA-256".into(),
        }
    }
}

impl FromStr for HttpAuthenticationDigestAlgorithm {
    type Err = HttpAuthenticationError

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "MD5" => Ok(Self::MD5),
            "SHA-256" => Ok(Self::SHA256),
            _ => Err(HttpAuthenticationError::UnsupportedDigestAlgorithm)
        }
    }
}
 */

#[derive(PartialEq)]
pub enum HttpAuthSchemeMethod {
    Empty,
    Basic,
    // Digest(HttpAuthSchemeDigestAlgorithm)
}


enum Base64UserPassEncodingError {
    ColonNotAllowedInUsername,
    // TODO: is non-ASCII TEXT is allowed?
    // see: https://datatracker.ietf.org/doc/html/rfc2617#section-2
}

fn encode_base64_user_pass(c: &Credential) -> Result<String, Base64UserPassEncodingError> {
    if c.username.find(':').is_some() {
        return Err(Base64UserPassEncodingError::ColonNotAllowedInUsername);
    }

    Ok(base64::encode(format!("{}:{}", c.username, c.password)))
}

enum Base64UserPassDecodingError { ColonNotFound, Base64DecodeError }
fn decode_base64_user_pass(s: &str) -> Result<Credential, Base64UserPassDecodingError> {
    let cre_b = if let Ok(cre_b) = base64::decode(s) {
        cre_b
    } else {
        return Err(Base64UserPassDecodingError::Base64DecodeError);
    };

    // TODO: What's the encoding of user-pass according to RFC 2617?
    let cre_s = if let Ok(cre_s) = String::from_utf8(cre_b) {
        cre_s
    } else {
        return Err(Base64UserPassDecodingError::Base64DecodeError);
    };

    if let Some((u_s, p_s)) = cre_s.split_once(':') {
        Ok(Credential {
            username: u_s.to_string(),
            password: p_s.to_string(),
        })
    } else {
        Err(Base64UserPassDecodingError::ColonNotFound)
    }
}

pub enum HttpAuthChallengeMessage {
    Empty,
    Basic { realm: String },
    // Digest(nonce, opaque, qop, algorithm),
}

impl HttpAuthChallengeMessage {
    pub fn _new() -> Self {
        HttpAuthChallengeMessage::Empty
        // realm: "Hello.Carpenter".to_string(),
    }
}

impl ToString for HttpAuthChallengeMessage {
    fn to_string(&self) -> String {
        match self {
            Self::Empty => String::from(""),
            Self::Basic { realm } =>
                format!("Basic realm=\"{}\"", realm), // TODO: check characters
        }
    }
}

pub enum HttpAuthCredentialMessage {
    Empty,
    Basic(Credential),
    // Digest(realm, uri, username, algorithm, nonce, nc, c-nonce, qop, response, opaque),
}


impl HttpAuthCredentialMessage {
    pub fn new() -> Self {
        Self::Empty
    }
}

impl FromStr for HttpAuthCredentialMessage {
    type Err = HttpAuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let view = HttpAuthMessage::from_str(s);

        println!("from_str {:?}", view.is_ok());

        let view = view.or(Err(Self::Err::UnexpectedMessageFormat))?;

        println!("scheme is basic {:?} {:?}", view.scheme, view.basic);
        match view.scheme.to_lowercase().as_str() {
            "basic" => {
                if view.basic.is_empty() || !view.params.is_empty() {
                    return Err(Self::Err::UnexpectedMessageFormat);
                }
                match decode_base64_user_pass(&view.basic[..]) {
                    Ok(cre) => Ok(Self::Basic(cre)),
                    Err(_) => Err(HttpAuthError::InvalidParameterValue),
                }
            },
            _ => {
                return Err(HttpAuthError::UnsupportedScheme);
            },
        }
    }
}



struct HttpAuthMessage {
    scheme: String,
    basic: String,
    params: Vec<(String, String)>,
}

enum HttpAuthMessageError {
    SyntaxError,
    // ParameterError,
}

impl FromStr for HttpAuthMessage {
    type Err = HttpAuthMessageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fn is_tchar(x: char) -> bool {
            "!#$%&'*+-.^_`|~".find(x).is_some() || x.is_ascii_alphanumeric()
        }

        fn get_token<'c>(s: &'c str) -> Option<&'c str> {
            match &s[..s.find(|x| !is_tchar(x)).unwrap_or(s.len())] {
                "" => None,
                o => Some(o),
            }
        }

        fn get_ows<'c>(s: &'c str) -> Option<&'c str> {
            Some(&s[..s.find(|x| !(x == ' ' || x == '\t')).unwrap_or(s.len())])
        }
        fn get_bws<'c>(s: &'c str) -> Option<&'c str> {
            Some(&s[..s.find(|x| !(x == ' ' || x == '\t')).unwrap_or(s.len())])
        }

        fn get_1sp<'c>(s: &'c str) -> Option<&'c str> {
            let i = s.find(|x| x != ' ').unwrap_or(s.len());
            if i == 0 { None } else { Some(&s[..i]) }
        }

        fn get_eof<'c>(s: &'c str) -> Option<&'c str> {
            if s.len() == 0 { Some(s) } else { None }
        }

        fn get_token68<'c>(s: &'c str) -> Option<&'c str> {
            let isc = |x: char| "-._~+/=".find(x).is_some() || x.is_ascii_alphanumeric();
            match &s[..s.find(|x| !isc(x)).unwrap_or(s.len())] {
                "" => None,
                o => Some(o),
            }
        }

        fn get_char<'c>(s: &str, c: &'c str) -> Option<&'c str> {
            if s.starts_with(c) { Some(c) } else { None }
        }

        fn get_quoted_string<'c>(ss: &'c str) -> Option<(&'c str, String)> {
            let mut t = String::from("");

            let is_qdtext = |c: char|
                c == '\t' || c == ' ' || c == '\x21' ||
                    '\x23' <= c && c <= '\x5B' ||
                    '\x5D' <= c && c <= '\x7E' ||
                    '\u{80}' <= c && c <= '\u{FF}'; // TODO: What's that?

            let is_qpair = |c: char|
                c == '\t' || c == ' ' || !c.is_control() || '\u{80}' <= c && c <= '\u{FF}';

            if ss.len() == 0 || ss.chars().nth(0).unwrap() != '"' {
                return None;
            }

            let mut i = 1;

            while i < ss.len() {
                match ss.chars().nth(i).unwrap() {
                    '"' => return Some((&ss[..(i+1)], t)),
                    '\\' if i+1 < ss.len() && is_qpair(ss.chars().nth(i+1).unwrap()) => {
                        t.push(ss.chars().nth(i+1).unwrap());
                        i += 2;
                    },
                    o if is_qdtext(o) => {
                        t.push(ss.chars().nth(i).unwrap());
                        i += 1;
                    },
                    _ => return None,
                }
            }

            return None;
        }

        fn consume<'c>(s: &'c str, g: &str) -> (&'c str, &'c str) {
            assert!(s.starts_with(g));
            (&s[g.len()..], &s[..g.len()])
        }

        let (s, scheme_s) = consume(s, get_token(s).ok_or(Self::Err::SyntaxError)?);
        let (s, _) = consume(s, get_1sp(s).ok_or(Self::Err::SyntaxError)?);

        let basic_s = if let Some(credential_s) = get_token68(s) {
            if credential_s.len() == s.len() { credential_s } else { &s[0..1] }
        } else {
            &s[0..1] // an empty &str
        };

        let mut params = Vec::new();

        if !basic_s.is_empty() {
            return Ok(Self {
                scheme: scheme_s.to_string(),
                basic: basic_s.to_string(),
                params,
            });
        }

        let ge = || HttpAuthMessageError::SyntaxError;
        loop {
            let (s, pkey) = consume(s, get_token(s).ok_or(ge())?);
            let (s, _) = consume(s, get_bws(s).ok_or(ge())?);
            let (s, _) = consume(s, get_char(s, "=").ok_or(ge())?);
            let (s, _) = consume(s, get_bws(s).ok_or(ge())?);

            let (s, pval) = if let Some(t) = get_token(s) {
                (consume(s, t).0, t.to_string())
            } else if let Some((t, p)) = get_quoted_string(s) {
                (consume(s, t).0, p.to_string())
            } else {
                return Err(ge());
            };

            params.push((pkey.to_string(), pval));

            if get_eof(s).is_some() {
                break;
            }

            let (s, _) = consume(s, get_ows(s).ok_or(ge())?);
            let (s, _) = consume(s, get_char(s, ",").ok_or(ge())?);
            let (_s, _) = consume(s, get_ows(s).ok_or(ge())?);
        }

        Ok(Self {
            scheme: scheme_s.to_string(),
            basic: basic_s.to_string(),
            params,
        })
    }
}

