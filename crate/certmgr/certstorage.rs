use std::{io, fs};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::Path;
use rcgen::{BasicConstraints, DistinguishedName, KeyPair, SerialNumber};
use rcgen::IsCa::Ca;
use crate::common::{HostName, Hostname};

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

    // create new cert if needed
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
    Ok(Some(anchor))
}


const CERTIFICATE_DIR: &str = "_certificates/tls_repack/";
const CERTIFICATE_TLS_REPACK_DIR: &str = "_certificates/tls_repack/";
const CERTIFICATE_ROOT_CA_DIR: &str = "_certificates/root_ca/";
const CERTIFICATE_TLS_SERVER_DIR: &str = "_certificates/tls_server/";
const ROOT_CA_CERTIFICATE_PATH: &str = "_certificates/root_ca/root_ca.crt";
const ROOT_CA_PRIVATE_KEY_PATH: &str = "_certificates/root_ca/root_ca.pkey.pem";
pub const ROOT_CA_FLAG_PATH: &str = "_certificates/root_ca/NEED_TO_INSTALL_ROOT_CA";


pub fn fetch_or_generate_tls_root_certificate() -> io::Result<()> {

    let cert_path = Path::new(ROOT_CA_CERTIFICATE_PATH);
    let pkey_path = Path::new(ROOT_CA_PRIVATE_KEY_PATH);

    if !(cert_path.exists() && pkey_path.exists()) {
        let key_pair = KeyPair::generate().unwrap();
        let mut cert_param = rcgen::CertificateParams::new(vec!["Root CA".to_string()]).unwrap();
        cert_param.is_ca = Ca(BasicConstraints::Unconstrained);
        let mut distinguish_name = DistinguishedName::new();
        distinguish_name.push(rcgen::DnType::CommonName, "_You_are_using_Carpenter");
        distinguish_name.push(rcgen::DnType::OrganizationName, "_You_are_using_Carpenter");
        cert_param.distinguished_name = distinguish_name;
        let cert = cert_param.self_signed(&key_pair).unwrap();

        let mut cert_file = fs::File::create(cert_path)?;
        cert_file.write_all(cert.pem().as_bytes())?;

        let mut pkey_file = fs::File::create(pkey_path)?;
        pkey_file.write_all(key_pair.serialize_pem().as_bytes())?;

        fs::File::create(Path::new(ROOT_CA_FLAG_PATH))?;
    }

    Ok(())
}


pub fn prepare_certificate_storage_filesystem_structure() {
    let dir_path_list = vec![
        CERTIFICATE_DIR,
        CERTIFICATE_TLS_REPACK_DIR,
        CERTIFICATE_ROOT_CA_DIR,
        CERTIFICATE_TLS_SERVER_DIR,
    ];

    for dp in dir_path_list.iter() {
        let path = Path::new(dp);
        if !path.exists() {
            fs::create_dir_all(path).unwrap();
        }
    }
}


pub fn sign_altname_certificate_from_root_ca(altname: String) -> io::Result<String> {
    let mut reader = io::BufReader::new(fs::File::open(ROOT_CA_PRIVATE_KEY_PATH)?);
    let mut key_pem = String::new();
    reader.read_to_string(&mut key_pem)?;
    let key_pair = rcgen::KeyPair::from_pem(key_pem.as_str()).unwrap();

    let mut reader = io::BufReader::new(fs::File::open(ROOT_CA_CERTIFICATE_PATH)?);
    let mut crt_pem = String::new();
    reader.read_to_string(&mut crt_pem)?;
    let issuer = rcgen::Issuer::from_ca_cert_pem(crt_pem.as_str(), key_pair).unwrap();

    let mut cert_param = rcgen::CertificateParams::new(vec![altname.clone()]).unwrap();
    let mut distinguish_name = DistinguishedName::new();
    distinguish_name.push(rcgen::DnType::CommonName, altname.as_str());
    distinguish_name.push(rcgen::DnType::OrganizationName, "Carpenter is repacking TLS stream");
    cert_param.distinguished_name = distinguish_name;
    let serial = generate_serial_number(altname.as_str());
    cert_param.serial_number = Some(SerialNumber::from_slice(serial.as_slice()));

    println!("cert_param.serial_number: {:?}", cert_param.serial_number);
    let key_pair = KeyPair::from_pem(key_pem.as_str()).unwrap();
    let sub_pem = cert_param.signed_by(&key_pair, &issuer).unwrap().pem();

    Ok(sub_pem)
}


fn get_tls_repack_private_key_path(_hostname: &Hostname) -> String {
    ROOT_CA_PRIVATE_KEY_PATH.to_string() // TODO
}

fn get_tls_repack_certificate_path_by_hostname(hostname: &Hostname) -> String {
    let n = hostname.to_string()
        .replace(".", "+")
        .replace(":", "+");
    format!("{}/tls_repack_({}).crt", CERTIFICATE_TLS_REPACK_DIR, n)
}


pub fn fetch_or_generate_tls_repack_certificate_file(hostname: &Hostname) -> io::Result<Vec<rustls::Certificate>> {
    let cert_path_s = get_tls_repack_certificate_path_by_hostname(hostname);
    let cert_path = Path::new(&cert_path_s);

    if !cert_path.exists() {
        let pem = sign_altname_certificate_from_root_ca(hostname.to_string())?;
        let mut file = fs::File::create(cert_path)?;
        let content = &pem;
        file.write_all(content.as_bytes())?;
    }

    assert!(cert_path.exists());

    // let mut file = fs::File::open(cert_path)?;
    // let mut contents = String::new();
    // file.read_to_string(&mut contents)?;
    // Ok(contents)
    Ok(crate::common::load_tls_certificate(cert_path.to_str().unwrap())?)
}

pub fn fetch_or_generate_tls_repack_private_key_file(hostname: &Hostname) -> io::Result<rustls::PrivateKey> {
    let key_path_s = get_tls_repack_private_key_path(hostname); // TODO
    let key_path = Path::new(&key_path_s);

    if !key_path.exists() {
        todo!("Generate TLS repack private key file");
    }

    assert!(key_path.exists());

    // let mut file = fs::File::open(key_path)?;
    // let mut contents = String::new();
    // file.read_to_string(&mut contents)?;
    // Ok(contents)

    Ok(crate::common::load_tls_private_key(key_path.to_str().unwrap())?)
}

fn generate_serial_number(input_string: &str) -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // 获取当前时间戳
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 结合时间戳和给定的字符串
    let combined = format!("{}{}", timestamp, input_string);

    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    let hash_result = hasher.finalize();

    // 将哈希结果转换为Vec<u8>
    hash_result.to_vec()
}
