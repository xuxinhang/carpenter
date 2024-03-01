use crate::authorization::httpauth::{
    HttpAuthChallengeMessage,
    HttpAuthCredentialMessage,
};
use super::HttpAuthError;

use crate::credential::{CredentialStore, Credential, load_client_credential_store};

pub struct HttpAuthClientSession {
    credential_store: CredentialStore,
}

impl HttpAuthClientSession {
    pub fn new() -> Self {
        Self {
            credential_store: load_client_credential_store(),
        }
    }

    pub fn get_credential(challenges: Vec<HttpAuthChallengeMessage>)
        -> HttpAuthCredentialMessage {
    	HttpAuthCredentialMessage::Empty
    }
}


