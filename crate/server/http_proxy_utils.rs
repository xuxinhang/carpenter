use std::str::FromStr;
use crate::common::HostAddr;


pub fn parse_http_proxy_message(msg_buf: &[u8]) -> Result<(usize, HostAddr, bool), String> {
    use crate::utils::http_message::parse_http_header;
    let r = parse_http_header(msg_buf);
    if r.is_none() {
        return Err("Invalid http message".to_string());
    }
    let (msg_header_length, msg_header_map) = r.unwrap();
    let use_http_tunnel_mode = msg_header_map[":method"].as_str() == "CONNECT";
    let host_str: &str = if use_http_tunnel_mode {
        &msg_header_map[":path"]
    } else {
        let path_str = &msg_header_map[":path"];
        let scheme_prefix = "http://";
        let pos_l = path_str.find(scheme_prefix);
        if pos_l.is_none() {
            return Err(format!("Invalid request path, only http supported: {:?}", path_str));
        }
        let pos_l = pos_l.unwrap() + scheme_prefix.len();
        let pos_r = &path_str[pos_l..].find("/").unwrap_or(path_str.len() - pos_l) + pos_l;
        &path_str[pos_l..pos_r]
    };

    // Get hostname from the string
    let r = HostAddr::from_str(host_str);
    if r.is_err() {
        return Err(format!("Invalid host {}", host_str));
    }
    let remote_host = r.unwrap();

    Ok((msg_header_length, remote_host, use_http_tunnel_mode))
}

