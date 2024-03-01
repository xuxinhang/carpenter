use std::str::FromStr;
use crate::authorization::httpauth::protocol::HttpAuthSchemeMethod;

use super::{
    HttpAuthError,
    HttpAuthCredentialMessage,
    HttpAuthChallengeMessage,
};
use crate::credential::{CredentialStore, Credential, load_server_credential_store};


pub fn get_allowed_scheme_methods() -> Vec<HttpAuthSchemeMethod> {
    vec![
        // HttpAuthSchemeMethod::Empty,
        HttpAuthSchemeMethod::Basic,
    ]
}

pub fn get_default_server_challenges() -> Vec<HttpAuthChallengeMessage> {
    // TODO: to associate with config file
    let realm = "Hello,Carpenter!";
    let mut messages = vec![];

    for scheme_method in get_allowed_scheme_methods() {
        messages.push(match scheme_method {
            HttpAuthSchemeMethod::Empty =>
                return vec![HttpAuthChallengeMessage::Empty],
            HttpAuthSchemeMethod::Basic =>
                HttpAuthChallengeMessage::Basic { realm: realm.to_string() },
        });
    }

    return messages;
}


pub struct HttpAuthServerSessionManager {
    credential_store: CredentialStore,
}

impl HttpAuthServerSessionManager {
    pub fn new() -> Self {
        Self {
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
        let allowed_scheme_methods = get_allowed_scheme_methods();
        let is_scheme_method_allowed = |s|
            allowed_scheme_methods.iter().find(|&x| x == &s).is_some();

        match auth {
            HttpAuthCredentialMessage::Empty => {
                if is_scheme_method_allowed(HttpAuthSchemeMethod::Empty) {
                    Ok(0)
                } else {
                    Err(HttpAuthError::InvalidIdentification)
                }
            },
            HttpAuthCredentialMessage::Basic(maybe_credential_s) => {
                println!("{:?}", maybe_credential_s);
                if !is_scheme_method_allowed(HttpAuthSchemeMethod::Basic) {
                    return Err(HttpAuthError::InvalidIdentification);
                }
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


