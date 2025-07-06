use std::cell::RefCell;
use std::io;
use std::rc::Rc;
use std::str::FromStr;
use crate::authorization::verifiers::{AuthenticationVerifier};
use crate::authorization::protocol::http_parser::{parse_credentials, CredentialsPart};

pub enum HttpAuthChallengeMessage {
    Empty,
    Basic { realm: String },
    // Digest(nonce, opaque, qop, algorithm),
}

impl HttpAuthChallengeMessage {
    pub fn get_http_string(&self) -> String {
        match self {
            HttpAuthChallengeMessage::Empty =>
                String::from(""),
            HttpAuthChallengeMessage::Basic { realm } =>
                format!("Basic realm=\"{}\"", realm),
        }
    }
}


pub enum HttpAuthorizationCredential {
    Basic {
        username: String,
        password: String,
    },
}

pub enum HttpAuthorizationCredentialParserError {
    ParseError,
    UnsupportedScheme,
}

impl FromStr for HttpAuthorizationCredential {
    type Err = HttpAuthorizationCredentialParserError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, cred) = parse_credentials(s)
            .map_err(|_| HttpAuthorizationCredentialParserError::ParseError)?;
        match scheme.as_str() {
            "Basic" => {
                if let Some(CredentialsPart::Token68(t)) = cred {
                    let decoded = base64::decode(t)
                        .map_err(|_| HttpAuthorizationCredentialParserError::ParseError)?;
                    let decoded_str = String::from_utf8(decoded)
                        .map_err(|_| HttpAuthorizationCredentialParserError::ParseError)?;
                    let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        return Ok(HttpAuthorizationCredential::Basic {
                            username: parts[0].to_string(),
                            password: parts[1].to_string(),
                        });
                    }
                }
                Err(HttpAuthorizationCredentialParserError::ParseError)
            }
            _ => Err(HttpAuthorizationCredentialParserError::UnsupportedScheme),
        }
    }
}

pub struct HttpAuthenticationServerManager {
    authentication_verifier: Rc<RefCell<Box<dyn AuthenticationVerifier>>>,
}

impl HttpAuthenticationServerManager {
    pub fn new(base_authentication_manager: Rc<RefCell<Box<dyn AuthenticationVerifier>>>) -> Self {
        HttpAuthenticationServerManager {
            authentication_verifier: base_authentication_manager,
        }
    }

    pub fn get_challenges(&self) -> Vec<HttpAuthChallengeMessage> {
        vec![
            HttpAuthChallengeMessage::Basic { realm: "Carpenter.Proxy".to_string() },
        ]
    }

    pub fn check_credentials(&self, maybe_credential: Option<HttpAuthorizationCredential>) -> io::Result<bool> {
        // let verifier = &crate::global::get_global_config().core.authentication_verifier;
        let verifier = self.authentication_verifier.borrow();
        match maybe_credential {
            None => {
                Ok(verifier.verify_credential(""))
            }
            Some(HttpAuthorizationCredential::Basic { username, password }) => {
                Ok(verifier.verify_credential(&format!("{}:{}", username, password)))
            }
            // _ => Ok(false),
        }
    }
}
