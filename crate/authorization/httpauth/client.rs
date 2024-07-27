use crate::authorization::httpauth::{
    HttpAuthChallengeMessage,
    HttpAuthCredentialMessage,
};

use crate::credential::{CredentialStore, load_client_credential_store};

pub struct HttpAuthClientSession {
    credential_store: CredentialStore, // only the first one is valid
}

impl HttpAuthClientSession {
    pub fn new() -> Self {
        Self {
            credential_store: load_client_credential_store(),
        }
    }

    pub fn get_credential(&self, challenges: Vec<HttpAuthChallengeMessage>)
        -> Option<HttpAuthCredentialMessage> {
        for challenge in challenges {
            match challenge {
                HttpAuthChallengeMessage::Empty => {
                    return Some(HttpAuthCredentialMessage::Empty);
                }
                HttpAuthChallengeMessage::Basic { realm: _ } => {
                    if let Some(cre) = self.credential_store.get_one_credential() {
                        return Some(HttpAuthCredentialMessage::Basic(cre.clone()));
                    }
                }
            }
        }
        None
    }
}
