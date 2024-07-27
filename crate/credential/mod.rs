use std::collections::HashMap;


#[derive(Clone, Debug)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

pub struct CredentialStore {
    pub credentials: HashMap<String, Credential>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    pub fn insert_credential(&mut self, cre: Credential)
                             -> Option<Credential> {
        self.credentials.insert(cre.username.to_string(), cre)
    }

    pub fn verify_credential(&self, maybe_cre: &Credential)
                             -> Option<&Credential> {
        if let Some(cre) = self.credentials.get(&maybe_cre.username) {
            if cre.password == maybe_cre.password {
                return Some(cre);
            }
        }

        None
    }

    pub fn get_one_credential(&self) -> Option<&Credential> {
        self.credentials.values().next()
    }
}

// TODO: More complicated with config file
pub fn load_server_credential_store() -> CredentialStore {
    let mut store = CredentialStore::new();
    store.insert_credential(Credential {
        username: "guest".to_string(),
        password: "12345".to_string(),
    });
    return store;
}

// TODO: More complicated with config file
pub fn load_client_credential_store() -> CredentialStore {
    let mut store = CredentialStore::new();
    store.insert_credential(Credential {
        username: "guess".to_string(),
        password: "12340".to_string(),
    });
    return store;
}

