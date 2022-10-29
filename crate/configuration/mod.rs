use std::fs;
use std::path::Path;
use std::io::{BufRead, BufReader, Read};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use crate::uri_match::{HostMatchTree};
use crate::common::{Hostname, HostAddr};


/* System initialize */
pub struct GlobalConfiguration {
    pub transformer_matcher: HostMatchTree<TransformerAction>,
    pub querier_matcher: HostMatchTree<QuerierAction>,
    pub core: CoreConfig,
}

pub fn load_default_configuration() -> GlobalConfiguration {
    // load core config file
    let file_name = "./config/core.toml";
    let mut reader = BufReader::new(fs::File::open(file_name).unwrap());
    let mut file_string = String::new();
    reader.read_to_string(&mut file_string).unwrap();
    let core_cfg = parse_core_config(&file_string);

    // load transformer matcher
    let file_name = "./config/transformer_matcher.txt";
    let reader = BufReader::new(fs::File::open(file_name).unwrap());
    let transformer_matcher = parse_transformer_matcher(reader);

    // load querier matcher from system's host file
    let mut tree = HostMatchTree::new();
    if core_cfg.dns_load_local_host_file {
        if let Some(file_path) = get_hosts_file_path() {
            let par = HostsFileParser::new(BufReader::new(fs::File::open(file_path).unwrap()));
            for (ip, domains) in par {
                for d in domains.iter() {
                    tree.insert(0, d, QuerierAction::To(ip.clone()))
                }
            }
        }
    }

    // load querier matcher from configuration file
    let file_name = "./config/querier_matcher.txt";
    let reader = BufReader::new(fs::File::open(file_name).unwrap());
    parse_querier_matcher(&mut tree, reader);
    let querier_matcher = tree;

    // construct global configuration structure
    GlobalConfiguration {
        transformer_matcher: transformer_matcher,
        querier_matcher: querier_matcher,
        core: core_cfg,
    }
}

impl GlobalConfiguration {
    pub fn get_transformer_action_by_host(&self, host: &HostAddr) -> Option<TransformerAction> {
        match host.0 {
            Hostname::Domain(ref s) => {
                self.transformer_matcher.get(host.1, s)
            }
            _ => None,
        }
    }
    pub fn get_querier_action_by_domain_name(&self, domain_name: &str) -> Option<QuerierAction> {
        self.querier_matcher.get(0, domain_name)
    }
}


/**
 * Transformer matcher config
 * Use different transformers for different domains
 */

fn is_matcher_config_file_line_valid(s: &str) -> bool {
    let s = s.trim_start();
    // ignore blank line
    if s.is_empty() {
        return false;
    }
    // ignore comment line
    if s.starts_with('#') {
        return false;
    }
    true
}

#[derive(Clone)]
pub enum TransformerAction {
    SniTransformer(String),
    DirectTransformer,
}

fn parse_transformer_matcher(reader: impl BufRead) -> HostMatchTree<TransformerAction> {
    let mut tree = HostMatchTree::new();

    for line in reader.lines() {
        let line = line.unwrap();
        if !is_matcher_config_file_line_valid(&line) {
            continue;
        }

        let (host_str, prof_str) = line.split_once('+').unwrap();
        let host_str = String::from(host_str.trim());
        let mut prof_str = String::from(prof_str.trim());
        prof_str.push(' ');

        let (hostname, port_str) = host_str.rsplit_once(':').unwrap_or((&host_str, "0"));
        let port = port_str.parse().unwrap_or(0) as u16;
        let hostname = hostname.trim();
        let (tf_type, tf_param) = prof_str.split_once(' ').unwrap();
        let prof = match tf_type {
            "sni" => TransformerAction::SniTransformer(tf_param.trim().to_string()),
            _ => TransformerAction::DirectTransformer,
        };

        tree.insert(port, hostname, prof);
    }

    tree
}


/**
 * Querier matcher config
 * Use different queriers for different domains
 */

#[derive(Clone)]
pub enum QuerierAction {
    To(String),
    Dns(String),
}

fn parse_querier_matcher(tree: &mut HostMatchTree<QuerierAction>, reader: impl BufRead) {
    for line in reader.lines() {
        let line = line.unwrap();
        if !is_matcher_config_file_line_valid(&line) {
            continue;
        }

        let (pattern_str, action_str) = line.split_once('+').unwrap();
        let hostname_str = pattern_str.trim();
        let (action_type_str, action_param_str) =
            action_str.split_once(' ').unwrap_or((action_str, ""));
        let action_param_str = action_param_str.trim_start();

        let action = match action_type_str {
            "dns" => QuerierAction::Dns(action_param_str.to_string()),
            "to" => QuerierAction::To(action_param_str.to_string()),
            _ => {
                panic!("Unknown querier pattern.");
            }
        };

        tree.insert(0, hostname_str, action);
    }
}


/**
 * Program core config
 * which consists of many items
 */
#[derive(Debug)]
pub enum DnsServerProtocol {
    Udp,
    Tls
}

#[derive(Debug)]
pub struct CoreConfig {
    pub env_openssl_path: String,
    pub inbound_http_enable: bool,
    pub inbound_http_listen: String,
    pub log_level: u8,
    pub dns_cache_expiration: u32,
    pub dns_load_local_host_file: bool,
    pub dns_server: HashMap<String, (DnsServerProtocol, SocketAddr)>,
}

fn parse_core_config(cfg_str: &str) -> CoreConfig {
    let mut cfg = CoreConfig {
        env_openssl_path: String::from("openssl"),
        inbound_http_enable: false,
        inbound_http_listen: String::new(),
        log_level: 5,
        dns_cache_expiration: 7200,
        dns_load_local_host_file: true,
        dns_server: HashMap::new(),
    };

    use toml::Value;
    let toml_root = cfg_str.parse::<Value>();
    if let Err(e) = toml_root {
        println!("Fail to parse core.toml: {:?}", e);
        return cfg;
    }
    let toml_root = toml_root.unwrap();
    let toml_root = toml_root.as_table().unwrap();

    if let Some(t) = toml_root.get("env").map(|x| x.as_table()).flatten() {
        cfg.env_openssl_path = t.get("openssl_path").map(|x| x.as_str()).flatten()
            .unwrap_or("openssl").to_string();
    } else {
        cfg.env_openssl_path = String::from("openssl");
    }

    if let Some(t) = toml_root.get("inbound-http") {
        let t = t.as_table().expect("inbound_http should be a table");
        cfg.inbound_http_enable =
            t.get("enable").map(|x| x.as_bool()).flatten().unwrap_or(true);
        cfg.inbound_http_listen =
            t.get("listen").map(|x| x.as_str()).flatten().unwrap_or("0.0.0.0:7890").to_string();
    } else {
        cfg.inbound_http_enable = false;
    }

    if let Some(t) = toml_root.get("log").map(|x| x.as_table()).flatten() {
        cfg.log_level = t.get("level").map(|x| x.as_integer()).flatten().unwrap_or(5) as u8;
    } else {
        cfg.log_level = 5;
    }

    if let Some(t) = toml_root.get("dns").map(|x| x.as_table()).flatten() {
        if let Some(i) = t.get("cache-expiration").map(|x| x.as_integer()).flatten() {
            cfg.dns_cache_expiration = i as u32;
        }
        if let Some(i) = t.get("load-local-host-file").map(|x| x.as_bool()).flatten() {
            cfg.dns_load_local_host_file = i;
        }
    }

    if let Some(t) = toml_root.get("dns-server").map(|x| x.as_table()).flatten() {
        let mut dns_server_map = HashMap::new();
        for (n, u) in t.iter() {
            if u.as_str().is_none() { continue; }
            let u = u.as_str().unwrap();

            if let Some((prot_str, addr_str)) = u.split_once("://") {
                let prot = match prot_str {
                    "udp" => DnsServerProtocol::Udp,
                    "tls" => DnsServerProtocol::Tls,
                    _ => {
                        println!("unknown protocol name: {}", prot_str);
                        continue;
                    }
                };
                let addr = if let Some((host_str, port_str)) = addr_str.split_once(':') {
                    let host = IpAddr::from_str(host_str).unwrap();
                    let port: u16 = port_str.parse().unwrap();
                    SocketAddr::new(host, port)
                } else {
                    let host = IpAddr::from_str(addr_str).unwrap();
                    let port = match prot {
                        DnsServerProtocol::Udp => 53,
                        DnsServerProtocol::Tls => 853,
                    };
                    SocketAddr::new(host, port)
                };
                dns_server_map.insert(String::from(n), (prot, addr));
            }
        }
        cfg.dns_server = dns_server_map;
    }

    cfg
}


fn get_hosts_file_path() -> Option<&'static str> {
    let p = "C:\\WINDOWS\\system32\\drivers\\etc\\hosts";
    if Path::new(p).exists() {
        return Some(p);
    }

    let p = "/etc/hosts";
    if Path::new(p).exists() {
        return Some(p);
    }

    None
}

struct HostsFileParser<R: BufRead> {
    buf_lines: std::io::Lines<R>,
}

impl<R: BufRead> HostsFileParser<R> {
    fn new(b: R) -> Self {
        Self { buf_lines: b.lines() }
    }
}

impl<R: BufRead> Iterator for HostsFileParser<R> {
    type Item = (String, Vec<String>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.buf_lines.next() {
                None => return None,
                Some(Err(_)) => continue,
                Some(Ok(s)) => {
                    let s = s.split_once('#').unwrap_or((&s, "")).0;
                    let mut substrings = s.split_whitespace().collect::<Vec<&str>>();
                    if substrings.len() < 2 {
                        continue;
                    }
                    let ip = Some(substrings.remove(0));
                    // IpAddr::from_str(substrings.remove(0));
                    return Some((
                        ip.unwrap().to_string(),
                        substrings.iter().map(|x| x.to_string()).collect(),
                    ));
                }
            }
        }
    }
}


