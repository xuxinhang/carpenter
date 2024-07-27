use std::str::{FromStr};
use std::collections::HashMap;
use crate::credential::{
    CredentialStore,
    Credential,
    load_server_credential_store,
};


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


pub struct HttpAuthChallengeMessage {
    realm: String, // realm is always available among all schemes
    scheme: HttpAuthChallengeMessageScheme,
}

enum HttpAuthChallengeMessageScheme {
    Empty,
    Basic,
    // Digest(nonce, opaque, qop, algorithm),
}

impl HttpAuthChallengeMessage {
    pub fn _new() -> Self {
        HttpAuthChallengeMessage {
            realm: "Hello.Carpenter".to_string(),
            scheme: HttpAuthChallengeMessageScheme::Empty,
        }
    }
}

impl ToString for HttpAuthChallengeMessage {
    fn to_string(&self) -> String {
        match self.scheme {
            HttpAuthChallengeMessageScheme::Empty => "".to_string(),
            HttpAuthChallengeMessageScheme::Basic =>
                // TODO: check invalid chars in realm
                format!("Basic realm=\"{}\"", self.realm),
        }
    }
}

pub enum HttpAuthCredentialMessage {
    Empty,
    Basic(String),
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

                if let Ok(cre_b) = base64::decode(view.basic) {
                    if let Ok(cre_s) = String::from_utf8(cre_b) {
                        return Ok(Self::Basic(cre_s));
                    }
                }

                return Err(HttpAuthError::InvalidParameterValue);
            },
            _ => {
                return Err(HttpAuthError::UnsupportedScheme);
            },
        }
    }
}


pub fn create_default_challenge_list() -> Vec<HttpAuthChallengeMessage> {
    let realm = "Hello,Carpenter!";
    let chg = HttpAuthChallengeMessage {
        realm: realm.to_string(),
        scheme: HttpAuthChallengeMessageScheme::Basic,
    };
    return vec![chg];
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


pub struct HttpAuthenticationSessionManager {
    allow_anonymous: bool,
    credential_store: CredentialStore,
}

impl HttpAuthenticationSessionManager {
    pub fn new() -> Self {
        Self {
            allow_anonymous: false,
            credential_store: load_server_credential_store(),
        }
    }

    pub fn authenticate_from_str(&self, authorization_field: Option<&str>)
        -> Result<usize, HttpAuthError> {
        let auth = if let Some(s) = authorization_field {
            println!("A {:?}", s);
            println!("B {:?}", HttpAuthCredentialMessage::from_str(s).is_err());
            HttpAuthCredentialMessage::from_str(s)
                .unwrap_or(HttpAuthCredentialMessage::new())
        } else {
            HttpAuthCredentialMessage::new()
        };

        self.authenticate(&auth)
    }

    pub fn authenticate(&self, auth: &HttpAuthCredentialMessage)
        -> Result<usize, HttpAuthError> {
        match auth {
            HttpAuthCredentialMessage::Empty => {
                if self.allow_anonymous {
                    Ok(0)
                } else {
                    Err(HttpAuthError::InvalidIdentification)
                }
            },
            HttpAuthCredentialMessage::Basic(maybe_credential_s) => {
                println!("{:?}", maybe_credential_s);
                let x = maybe_credential_s.split_once(':');
                if x.is_none() {
                    return Err(HttpAuthError::InvalidIdentification);
                }
                let x = x.unwrap();
                let maybe_credential = Credential {
                    username: x.0.to_string(),
                    password: x.1.to_string(),
                };

                if self.credential_store.verify_credential(maybe_credential).is_none() {
                    Err(HttpAuthError::InvalidIdentification)
                } else {
                    Ok(0)
                }
            },
            // _ => Err(HttpAuthenticationError::UnsupportedScheme),
        }
    }
}

