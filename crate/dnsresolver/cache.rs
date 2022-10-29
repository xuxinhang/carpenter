use std::net::IpAddr;
use crate::uri_match::HostMatchTree;


fn get_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap()
        .as_secs() as u64
}


pub struct DnsCacheHolder {
    match_tree: HostMatchTree<(IpAddr, u64)>,
    // last_flush_timestamp: u64,
}

impl DnsCacheHolder {
    pub fn new() -> Self {
        Self {
            match_tree: HostMatchTree::new(),
        }
    }

    pub fn store(&mut self, domain: &str, ip: IpAddr) {
        let expiration_time = get_timestamp()
            + crate::global::get_global_config().core.dns_cache_expiration as u64;
        self.match_tree.insert(0, domain, (ip, expiration_time));
        ()
    }

    pub fn get(&self, domain: &str) -> Option<IpAddr> {
        match self.match_tree.get(0, domain) {
            None => return None,
            Some((ip, ts)) => {
                if ts < get_timestamp() {
                    return None;
                } else {
                    return Some(ip);
                }
            }
        }
    }
}
