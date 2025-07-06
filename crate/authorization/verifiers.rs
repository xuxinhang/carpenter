use std::io;
use std::collections::HashSet;


pub trait AuthenticationVerifier {
    fn verify_credential(&self, s: &str) -> bool;
}

pub struct SimpleAuthenticationVerifier {
    credentials: HashSet<String>,
}

impl SimpleAuthenticationVerifier {
    pub fn new(credentials: &Vec<String>) -> Self {
        Self {
            credentials: HashSet::from_iter(credentials.clone()),
        }
    }
}

impl AuthenticationVerifier for SimpleAuthenticationVerifier {
    fn verify_credential(&self, s: &str) -> bool {
        self.credentials.contains(s)
    }
}

pub fn load_simple_credentials_from_file(file_path: &str) -> io::Result<Vec<String>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let credential_lines = BufReader::new(File::open(file_path)?)
        .lines()
        .map(|line| line.unwrap_or(String::new()))
        .filter(|line| line.len() > 0 && !line.starts_with('#'))
        .collect();

    Ok(credential_lines)
}


pub struct FreeAuthenticationVerifier();

impl FreeAuthenticationVerifier {
    pub fn new() -> Self {
        Self()
    }
}

impl AuthenticationVerifier for FreeAuthenticationVerifier {
    fn verify_credential(&self, _s: &str) -> bool {
        true
    }
}
