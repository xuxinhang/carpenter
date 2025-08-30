use std::{io, fs};
use std::io::{Read, Write};
use std::path::Path;
use rcgen::{BasicConstraints, DistinguishedName, KeyPair, SerialNumber};
use rcgen::IsCa::Ca;
use rustls::internal::msgs::enums::ExtensionType::SignatureAlgorithms;
use crate::common::Hostname;


const CERTIFICATE_DIR: &str = "_certificates/tls_repack/";
const CERTIFICATE_TLS_REPACK_DIR: &str = "_certificates/tls_repack/";
const CERTIFICATE_ROOT_CA_DIR: &str = "_certificates/root_ca/";
const CERTIFICATE_TLS_SERVER_DIR: &str = "_certificates/tls_server/";
pub const ROOT_CA_CERTIFICATE_PATH: &str = "_certificates/root_ca/root_ca.crt";
const ROOT_CA_PRIVATE_KEY_PATH: &str = "_certificates/root_ca/root_ca.pkey.pem";
pub const ROOT_CA_FLAG_PATH: &str = "_certificates/root_ca/NEED_TO_INSTALL_ROOT_CA";


pub fn fetch_or_generate_tls_root_certificate() -> io::Result<()> {

    let cert_path = Path::new(ROOT_CA_CERTIFICATE_PATH);
    let pkey_path = Path::new(ROOT_CA_PRIVATE_KEY_PATH);

    if !(cert_path.exists() && pkey_path.exists()) {
        let key_pair = KeyPair::generate().unwrap();
        let mut cert_param = rcgen::CertificateParams::new(vec![]).unwrap();
        cert_param.is_ca = Ca(BasicConstraints::Unconstrained);

        let mut distinguish_name = DistinguishedName::new();
        distinguish_name.push(rcgen::DnType::CommonName, "You_are_using_Carpenter");
        distinguish_name.push(rcgen::DnType::OrganizationName, "You_are_using_Carpenter");
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

    let mut cert_param =
        rcgen::CertificateParams::new(vec![altname.clone()]).unwrap();
    
    let mut distinguish_name = DistinguishedName::new();
    distinguish_name.push(rcgen::DnType::CommonName, altname.as_str());
    distinguish_name.push(rcgen::DnType::OrganizationName, "Carpenter_is_repacking_TLS_stream");
    distinguish_name.push(rcgen::DnType::OrganizationalUnitName, "Carpenter");
    distinguish_name.push(rcgen::DnType::CountryName, "CN");
    distinguish_name.push(rcgen::DnType::LocalityName, "CQ");
    distinguish_name.push(rcgen::DnType::StateOrProvinceName, "CQ");
    cert_param.distinguished_name = distinguish_name;
    
    let serial = generate_serial_number(altname.as_str());
    cert_param.serial_number = Some(SerialNumber::from_slice(&serial.as_slice()[..20]));

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

pub fn pem_to_der(pem_content: &str) -> Vec<u8> {
    // 解析PEM内容
    use pem::parse;
    let pem = parse(pem_content).expect("Failed to parse PEM");
    // 提取DER数据
    let der = pem.contents().to_vec();
    der
}