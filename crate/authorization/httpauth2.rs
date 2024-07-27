use std::str::{FromStr};
use std::collections::HashMap;


#[derive(Debug)]
pub enum HttpAuthenticationError {
    UnexpectedMessageFormat,
    InvalidParameterValue,
    UnsupportedScheme,
    UnsupportedDigestAlgorithm,
    UnexpectedMessageField,
    InvalidIdentification,
    Other(u8)
}

// enum HttpAuthenticationDigestAlgorithm { MD5, SHA256 }

// impl ToString for HttpAuthenticationDigestAlgorithm {
//     pub fn to_string(&self) -> String {
//         match self {
//             Self::MD5 => "MD5".into(),
//             Self::SHA256 => "SHA-256".into(),
//         }
//     }
// }

// impl FromStr for HttpAuthenticationDigestAlgorithm {
//     type Err = HttpAuthenticationError

//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         match s {
//             "MD5" => Ok(Self::MD5),
//             "SHA-256" => Ok(Self::SHA256),
//             _ => Err(HttpAuthenticationError::UnsupportedDigestAlgorithm)
//         }
//     }
// }

struct HttpAuthenticationCredential {
    username: String,
    password: String,
}


struct CredentialStore {
    credentials: HashMap<String, HttpAuthenticationCredential>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    pub fn insert_credential(&mut self, cre: HttpAuthenticationCredential)
                             -> Option<HttpAuthenticationCredential> {
        self.credentials.insert(cre.username.to_string(), cre)
    }

    pub fn verify_credential(&self, maybe_cre: HttpAuthenticationCredential)
                             -> Option<&HttpAuthenticationCredential> {
        if let Some(cre) = self.credentials.get(&maybe_cre.username) {
            if cre.password == maybe_cre.password {
                return Some(cre);
            }
        }

        None
    }
}

fn load_credential_store() -> CredentialStore {
    let mut store = CredentialStore::new();
    store.insert_credential(HttpAuthenticationCredential {
        username: "guest".to_string(),
        password: "12345".to_string(),
    });
    return store;
}

pub struct HttpAuthenticationChallenge {
    realm: String,
    scheme: HttpAuthenticationChallengeScheme,
}

enum HttpAuthenticationChallengeScheme {
    Empty,
    Basic,
    // pub nonce: Option<String>,
    // pub opaque: Option<String>,
    // pub qop: Option<String>,
    // pub algorithm: Option<String>,
}

impl HttpAuthenticationChallenge {
    pub fn _new() -> Self {
        HttpAuthenticationChallenge {
            realm: "Hello.Carpenter".to_string(),
            scheme: HttpAuthenticationChallengeScheme::Empty,
        }
    }
}

impl ToString for HttpAuthenticationChallenge {
    fn to_string(&self) -> String {
        match self.scheme {
            HttpAuthenticationChallengeScheme::Empty => "".to_string(),
            HttpAuthenticationChallengeScheme::Basic =>
            // TODO: check invalid chars in realm
                format!("Basic realm=\"{}\"", self.realm),
        }
    }

    // fn to_string(&self) -> String {
    //     let ss = self.scheme.to_string() + " "
    //     let ssappend = |k, v| {
    //         if let Some(x) = v {
    //             ss += format!("{k}={x},") // TODO: maybe some not allowed characters
    //         }
    //     }
    //     let ssappendquote = |k, v| {
    //         if let Some(x) = v {
    //             ss += format!("{k}=\"{x}\",") // TODO: maybe some not allowed characters
    //         }
    //     }
    //     ss += ssappendquote("realm", self.realm);
    //     ss += ssappendquote("nonce", self.nonce);
    //     ss += ssappendquote("opaque", self.opaque);
    //     ss += ssappend("qop", self.qop);
    //     ss += ssappend("algorithm", self.algorithm);
    // }
}

pub fn create_default_challenge_list() -> Vec<HttpAuthenticationChallenge> {
    let realm = "Hello,Carpenter!";
    let chg = HttpAuthenticationChallenge {
        realm: realm.to_string(),
        scheme: HttpAuthenticationChallengeScheme::Basic,
    };
    return vec![chg];
}



pub enum HttpAuthenticationAuthorization {
    Empty,
    Basic(String),
}

/*
struct HttpAuthenticationAuthorization {
    pub scheme: HttpAuthenticationScheme,

    // Basic
    pub basic: Option<String>,

    // Digest
    pub realm: Option<String>,
    pub uri: Option<String>,
    pub username: Option<String>,
    pub algorithm: Option<HttpAuthenticationDigestAlgorithm>,
    pub nonce: Option<String>,
    pub nc: Option<usize>,
    pub cnonce: Option<String>,
    pub qop: Option<String>,
    pub response: Option<String>,
    pub opaque: Option<String>,
}
*/

impl HttpAuthenticationAuthorization {
    pub fn new() -> Self {
        Self::Empty
    }
}

impl FromStr for HttpAuthenticationAuthorization {
    type Err = HttpAuthenticationError;

    /* fn from_str(s: &str) -> Result<Self, Self::Err> {
        // let auth = Self::new()
        // let (scheme, params_list) = parse_authentication_field(s)
        //     .ok_or(HttpAuthenticationError::UnexpectedMessageFormat)?;
        let s = s.trim();
        if s.len() == 0 {
            return Ok(Self::Empty);
        }

        // parse
        fn is_tchar(x: char) -> bool {
            "!#$%&'*+-.^_`|~".find(x).is_some() || x.is_ascii_alphanumeric()
        }

        fn get_token<'c>(s: &'c str) -> Option<&'c str> {
            match &s[..s.find(|x| !is_tchar(x)).unwrap_or(s.len())] {
                "" => None,
                o => Some(o),
            }
        }

        fn get_token68<'c>(s: &'c str) -> Option<&'c str> {
            let isc = |x: char| "-._~+/=".find(x).is_some() || x.is_ascii_alphanumeric();
            match &s[..s.find(|x| !isc(x)).unwrap_or(s.len())] {
                "" => None,
                o => Some(o),
            }
        }

        fn get_1sp<'c>(s: &'c str) -> Option<&'c str> {
            let i = s.find(|x| x != ' ').unwrap_or(s.len());
            if i == 0 { None } else { Some(&s[..i]) }
        }

        fn consume<'c>(s: &'c str, g: &str) -> (&'c str, &'c str) {
            (&s[g.len()..], &s[..g.len()])
        }

        let (s, scheme_s) = consume(s,
            get_token(s).ok_or(HttpAuthenticationError::UnexpectedMessageFormat)?);
        let (s, _) = consume(s,
            get_1sp(s).ok_or(HttpAuthenticationError::UnexpectedMessageFormat)?);

        match scheme_s {
            "Basic" => {
                if let Some(credential_s) = get_token68(s) {
                    if let Ok(cre_b) = base64::decode(credential_s) {
                        if let Ok(cre_s) = String::from_utf8(cre_b) {
                            return Ok(Self::Basic(cre_s));
                        }
                    }
                    return Err(HttpAuthenticationError::UnexpectedMessageFormat);
                } else {
                    return Err(HttpAuthenticationError::UnexpectedMessageFormat);
                }
            },
            _ => {
                return Err(HttpAuthenticationError::UnsupportedScheme);
            },
        }

        // let (s, _) = consume(s, get_1sp(s)?);


        // auth.scheme = scheme.parse()?;

        // let params = HashMap::from(params_list);
        // let unquote = |s| {
        //     if s[0] != '"' { return s; }
        //     assert!(s[s.len()-1] == '"');
        //     return s[1..(s.len()-1)];
        // }
        // let unquote_then_to_string = |_| unquote(_).to_string()

        // auth.basic = params.get("_").map(unquote_then_to_string)
        // auth.realm = params.get("realm").map(unquote_then_to_string)
        // auth.uri = params.get("uri").map(unquote_then_to_string)
        // auth.username = params.get("username").map(unquote_then_to_string)
        // auth.algorithm = params.get("algorithm").map(str::parse)
        // auth.nonce = params.get("nonce").map(unquote_then_to_string)
        // auth.nc = params.get("nc").map(|_| usize::from_str_radix(_, 16))
        // auth.cnonce = params.get("cnonce").map(unquote_then_to_string)
        // auth.qop = params.get("qop").map(unquote_then_to_string)
        // auth.response = params.get("response").map(unquote_then_to_string)
        // auth.opaque = params.get("opaque").map(unquote_then_to_string)
    } */

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let view = AuthenticationFieldTextView::from_str(s);

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

                return Err(HttpAuthenticationError::InvalidParameterValue);
            },
            _ => {
                return Err(HttpAuthenticationError::UnsupportedScheme);
            },
        }
    }
}



struct AuthenticationFieldTextView {
    scheme: String,
    basic: String,
    params: Vec<(String, String)>,
}

enum AuthenticationFieldTextViewError {
    SyntaxError,
    // ParameterError,
}

impl FromStr for AuthenticationFieldTextView {
    type Err = AuthenticationFieldTextViewError;

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

        let ge = || AuthenticationFieldTextViewError::SyntaxError;
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

// fn parse_authentication_field(ss: &str) -> Option<(&str, Vec<(&str,&str)>)> {
//     let is_tchar = |x: char|
//         "!#$%&'*+-.^_`|~".find(x).is_some() || char::is_ascii_alphanumeric(x);

//     let get_token = |s| match s[..s.find(|x| !is_tchar(x)).unwrap_or(s.len())] {
//         "" => None,
//         _ => Some(_)
//     };

//     let get_ows = |s| s[..s.find(|x| !(x == ' ' || x == '\t')).unwrap_or(s.len())];
//     let get_bws = get_ows;

//     let get_1sp = |s| {
//         let i = s.find(|x| x != ' ').unwrap_or(s.len())
//         if i == 0 { None } else { s[..i] }
//     };

//     let get_token68 = |s| {
//         let isc = |x: char| "-._~+/=".find(x).is_some() || char::is_ascii_alphanumeric(x);
//         match s[..s.find(|x| !isc(x)).unwrap_or(s.len())] {
//             "" => None,
//             _ => Some(_)
//         }
//     };

//     let get_char = |s, c| if s[0] == c { Some(c) } else { None };

//     let get_quoted_string = |ss| {
//         let t = String::from("")
//         let s = ss

//         let (t, s) = consume_into(t, s, get_char(s, '"'))

//         let i = 0
//         while i < s.len() {
//             let j = s[i..].find('"')?;
//             if j >= 1 && s[j-1] == '\\' {
//                 i = j + 1
//             } else {
//                 i = j
//                 break
//             }
//         }
//         t.push_str(s[..i]);
//         s = s[i..];

//         let (t, s) = consume_into(t, s, get_char(s, '"'))

//         assert!(t.len() + s.len() == ss.len());
//         Some(ss[...t.len()])
//     };

//     let consume_into = |t: String, s, g| {
//         if g.is_none() { return None }
//         t.push_str(g);
//         (t, s[g.len()..])
//     };

//     let consume = |s, g| (s[g.len()..], g);

//     let get_eof = |s| if s.len() == 0 { Some(s) } else { None };

//     let s = ss.trim_start();
//     let (s, auth_scheme) = consume(s, get_token(s)?);
//     let (s, _) = consume(s, get_1sp(s)?);

//     if get_eof(s).is_some() {
//         return Some((auth_scheme, vec![]))
//     }

//     if let Some(basic_credential) = get_token68(s) {
//         return Some((auth_scheme, vec![('_', basic_credential)]));
//     }

//     // auth-param
//     let params = Vec::new();
//     loop {
//         let (s, pkey) = consume(s, get_token(s)?);
//         let (s, _) = consume(s, get_bws(s)?);
//         let (s, _) = consume(s, get_char(s, '=')?);
//         let (s, _) = consume(s, get_bws(s)?);
//         let (s, pval) = consume(s, get_token(s).or(get_quoted_string(s))?);
//         params.insert(pkey, pval);

//         if get_eof(s).is_some() {
//             params.push((pkey, pval))
//             return Some((auth_scheme, params))
//         }

//         let (s, _) = consume(s, get_ows(s)?);
//         let (s, _) = consume(s, get_char(s, ',')?)
//         let (s, _) = consume(s, get_ows(s)?);
//     }
// }



// pub struct HttpAuthenticationSessionManager {
//     verify_hub: Rc<UserVerifyHub>,
//     session_opaque: String,
//     session_realm: String,
//     last_nonce: String,
//     session_nc: usize,
// }

// impl HttpAuthenticationSessionManager {
//     pub fn new(verify_hub: Rc<UserVerifyHub>) -> Self {
//         let default_realm = "Carpenter".into()
//         let deafult_opaque = base64::encode(format!(
//             "Carpenter@{}",
//             std::time::SystemTime::now()
//                 .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()
//             ));

//         Self {
//             verify_hub,
//             session_opaque: deafult_opaque,
//             session_realm: default_realm,
//             session_nc: 0,
//         }
//     }

//     pub fn get_challenges(&self) -> Vec<HttpAuthenticationChallenge> {
//         // provide any allowed schemes and their parameters
//         let challenges = Vec::new();

//         // generate and save nonce
//         self.last_nonce = generate_nonce_string()

//         let c = HttpAuthenticationChallenge::new();
//         c.scheme = HttpAuthenticationScheme::Basic;
//         c.realm = self.session_realm.clone();
//         challenges.push(c);

//         let c = HttpAuthenticationChallenge::new();
//         c.scheme = HttpAuthenticationScheme::Digest;
//         c.realm = self.session_realm.clone();
//         c.nonce = self.last_nonce.clone();
//         c.opaque = self.session_opaque.clone();
//         c.algorithm = "MD5".into();
//         challenges.push(c);

//         return challenges;
//     }

//     pub fn authenticate_from_str(&self, authorization_field: Option<&str>)
//         -> Result<usize, HttpAuthenticationError> {
//         let auth = authorization_field
//             .map(HttpAuthenticationAuthorization::from_str)
//             .transpose()?;
//         return self.authenticate(auth);
//     }

//     pub fn authenticate(&self, auth: Option<&HttpAuthenticationAuthorization>)
//         -> Result<usize, HttpAuthenticationError> {
//         if auth.is_none() {
//             return Ok(self.session_nc);
//         }

//         return Err(HttpAuthenticationError::UnsupportedScheme);
//     }
// }

// fn generate_nonce_string() -> String {
//     use textnonce::TextNonce;
//     TextNonce::sized_urlsafe(44).unwrap().into_string()
// }


pub struct HttpAuthenticationSessionManager {
    allow_annoymous: bool,
    credential_store: CredentialStore,
}

impl HttpAuthenticationSessionManager {
    pub fn new() -> Self {
        Self {
            allow_annoymous: false,
            credential_store: load_credential_store(),
        }
    }

    pub fn authenticate_from_str(&self, authorization_field: Option<&str>)
                                 -> Result<usize, HttpAuthenticationError> {
        let auth = if let Some(s) = authorization_field {
            println!("A {:?}", s);
            println!("B {:?}", HttpAuthenticationAuthorization::from_str(s).is_err());
            HttpAuthenticationAuthorization::from_str(s)
                .unwrap_or(HttpAuthenticationAuthorization::new())
        } else {
            HttpAuthenticationAuthorization::new()
        };

        self.authenticate(&auth)
    }

    pub fn authenticate(&self, auth: &HttpAuthenticationAuthorization)
                        -> Result<usize, HttpAuthenticationError> {
        match auth {
            HttpAuthenticationAuthorization::Empty => {
                if self.allow_annoymous {
                    Ok(0)
                } else {
                    Err(HttpAuthenticationError::InvalidIdentification)
                }
            },
            HttpAuthenticationAuthorization::Basic(maybe_credential_s) => {
                println!("{:?}", maybe_credential_s);
                let x = maybe_credential_s.split_once(':');
                if x.is_none() {
                    return Err(HttpAuthenticationError::InvalidIdentification);
                }
                let x = x.unwrap();
                let maybe_credential = HttpAuthenticationCredential {
                    username: x.0.to_string(),
                    password: x.1.to_string(),
                };

                if self.credential_store.verify_credential(maybe_credential).is_none() {
                    Err(HttpAuthenticationError::InvalidIdentification)
                } else {
                    Ok(0)
                }
            },
            // _ => Err(HttpAuthenticationError::UnsupportedScheme),
        }
    }
}

