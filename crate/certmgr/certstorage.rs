use std::{io, fs};
use std::net::IpAddr;
use crate::common::HostName;

fn get_cert_file_name_by_hostname(host_name: Option<HostName>) -> io::Result<(String, String)> {
    let global_config = crate::global::get_global_config();
    let openssl_path = global_config.core.env_openssl_path.clone();

    let mut alt_names_dns: Option<String> = None;
    let mut alt_names_ip: Option<String> = None;

    let (crt_file_name, csr_file_name, cfg_file_name) = match host_name {
        Some(HostName::IpAddress(IpAddr::V4(v))) => {
            alt_names_ip = Some(format!("{}", v));
            let n = format!("{}", v).replace(".", "_");
            let crt_file_name = format!("tls.ipv4_{}.crt.crt", n);
            let csr_file_name = format!("tls.ipv4_{}.csr.pem", n);
            let cfg_file_name = format!("tls.ipv4_{}.cfg.pem", n);
            (crt_file_name, csr_file_name, cfg_file_name)
        }
        Some(HostName::IpAddress(IpAddr::V6(v))) => {
            alt_names_ip = Some(format!("{}", v));
            let n = format!("{}", v).replace(":", "_");
            let crt_file_name = format!("tls.ipv6_{}.crt.crt", n);
            let csr_file_name = format!("tls.ipv6_{}.csr.pem", n);
            let cfg_file_name = format!("tls.ipv6_{}.cfg.pem", n);
            (crt_file_name, csr_file_name, cfg_file_name)
        }
        Some(HostName::DomainName(v)) => {
            alt_names_dns = Some(String::from(v.as_str()));
            let n = format!("{}", v).replace(".", "_");
            let crt_file_name = format!("tls.dns_{}.crt.crt", n);
            let csr_file_name = format!("tls.dns_{}.csr.pem", n);
            let cfg_file_name = format!("tls.dns_{}.cfg.pem", n);
            (crt_file_name, csr_file_name, cfg_file_name)
        }
        None => {
            let crt_file_name = format!("tls.none.crt.crt");
            let csr_file_name = format!("tls.none.csr.pem");
            let cfg_file_name = format!("tls.none.cfg.pem");
            (crt_file_name, csr_file_name, cfg_file_name)
        }
    };
    let file_path_prefix = "_certs/issued/";
    let crt_file_name = format!("{}{}", file_path_prefix, crt_file_name);
    let csr_file_name = format!("{}{}", file_path_prefix, csr_file_name);
    let cfg_file_name = format!("{}{}", file_path_prefix, cfg_file_name);

    // create new cert if need
    let cfg_tmpl_name = String::from("config/sub_cert_conf_tmpl.txt");
    let key_file_name = format!("_certs/root.key.pem");

    if !std::path::Path::new(&crt_file_name).exists() {
        wd_log::log_info_ln!("Creating TLS certificate ({:?}{:?})...", alt_names_dns, alt_names_ip);

        // generate request conf file
        let cfg_tmpl = fs::read_to_string(cfg_tmpl_name)?;
        let cfg_cont = cfg_tmpl
            .replace("{{ALT_NAMES_BOTH_EN}}", if alt_names_ip.is_some() || alt_names_dns.is_some() {""} else {"#"})
            .replace("{{ALT_NAMES_DNS_EN}}", if alt_names_dns.is_some() {""} else {"#"} )
            .replace("{{ALT_NAMES_DNS_VAL}}", &alt_names_dns.unwrap_or("0".to_string()))
            .replace("{{ALT_NAMES_IP_EN}}", if alt_names_ip.is_some() {""} else {"#"} )
            .replace("{{ALT_NAMES_IP_VAL}}", &alt_names_ip.unwrap_or("0".to_string()));
        fs::write(&cfg_file_name, &cfg_cont)?;

        std::process::Command::new(&openssl_path)
            .args([
                "req", "-new",
                "-out", &csr_file_name,
                "-key", &key_file_name,
                "-config", &cfg_file_name,
            ])
            .output()?;
        std::process::Command::new(&openssl_path)
            .args([
                "x509", "-req",
                "-in", &csr_file_name,
                "-days", "36500",
                "-CA", "_certs/root.crt.crt",
                "-CAkey",  "_certs/root.key.pem",
                "-extfile", &cfg_file_name,
                "-extensions", "req_extensions",
                "-out", &crt_file_name,
                "-CAcreateserial",
            ])
            .output()?;
        std::fs::remove_file(csr_file_name)?;
        std::fs::remove_file(cfg_file_name)?;
    }

    Ok((crt_file_name, key_file_name))
}

pub fn get_cert_data_by_hostname(host_name: Option<HostName>)
    -> io::Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
    let (cert_file_name, pkey_file_name) = get_cert_file_name_by_hostname(host_name)?;
    let cert_data = crate::common::load_tls_certificate(&cert_file_name)?;
    let pkey_data = crate::common::load_tls_private_key(&pkey_file_name)?;
    Ok((cert_data, pkey_data))
}

pub fn get_other_cert_data(crt_file_name: &str) -> io::Result<Vec<rustls::Certificate>> {
    let file_path_prefix = "_certs/issued/";
    let crt_file_name = format!("{}{}", file_path_prefix, crt_file_name);
    let cert_data = crate::common::load_tls_certificate(&crt_file_name)?;
    Ok(cert_data)
}

pub fn get_other_trust_anchor_data(crt_file_name: &str) -> io::Result<Option<rustls::OwnedTrustAnchor>> {
    let file_path_prefix = "_certs/";
    let crt_file_name = format!("{}{}", file_path_prefix, crt_file_name);

    let certfile = fs::File::open(crt_file_name)?;
    let items = rustls_pemfile::read_all(&mut io::BufReader::new(certfile))?;

    let der = match items.first().unwrap() {
        rustls_pemfile::Item::X509Certificate(dat) => dat,
        _ => return Ok(None),
    };

    let ta = webpki::TrustAnchor::try_from_cert_der(&der).unwrap();
    let anchor = rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
        ta.subject,
        ta.spki,
        ta.name_constraints,
    );
    return Ok(Some(anchor));
}
