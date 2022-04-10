pub mod event_loop;
pub mod proxy_http;
pub mod http_header_parser;
pub mod transformer;
pub mod configuration;
pub mod proxy_client;
pub mod common;
pub mod uri_match;
pub mod dnsresolver;
pub mod global;


use std::rc::Rc;
use event_loop::EventLoop;


fn main() {
    print!("Hello, mio!\n");

    // intialize global static variables
    global::init_global_stuff();

    // load config from file
    wd_log::log_info_ln!("Loading config...");
    let conf = Rc::new(configuration::load_default_configuration());
    global::publish_global_config(conf.clone());

    // customize logger
    wd_log::set_level(wd_log::Level::from(conf.core.log_level));

    // prepare root certificates
    if let Err(e) = check_and_prepare_root_certificate() {
        wd_log::log_error_ln!("Fail to prepare certificates: {:?}", e);
        panic!();
    }

    // start server and event loop
    let mut el = EventLoop::new(1024).unwrap();

    start_proxy_server(&mut el);

    match el.start_loop() {
        Ok(()) => {
            println!("Event loop ends.");
        }
        Err(e) => {
            println!("Event lopp error\n{:?}", e);
        }
    }
}


fn check_and_prepare_root_certificate() -> std::io::Result<()> {
    use std::path::Path;
    use std::fs;

    let root_crt_file_path = "./_certs/root.crt.crt";
    let root_key_file_path = "./_certs/root.key.pem";
    let root_cfg_file_path = "./config/root_cert_config.txt";

    let p = Path::new("./_certs");
    if !p.exists()  {
        fs::create_dir(p)?;
    }

    let p = Path::new("./_certs/issued");
    if !p.exists()  {
        fs::create_dir(p)?;
    }

    let note_file_path = Path::new("./_certs/NEED_TO_INSTALL_ROOT_CA");
    let openssl_path = crate::global::get_global_config().core.env_openssl_path.as_str();

    if !Path::new(root_crt_file_path).exists()
        || !Path::new(root_key_file_path).exists()
    {
        let p = Path::new(root_cfg_file_path);
        if !p.exists() {
            fs::File::open(p)?; // generate an error
        }
        std::process::Command::new(&openssl_path)
            .args([
                "req", "-new", "-x509",
                "-newkey", "rsa:2048", "-nodes", "-keyout", root_key_file_path,
                "-days", "36500",
                "-out", root_crt_file_path,
                "-config", root_cfg_file_path,
            ])
            .output()?;
        if !note_file_path.exists() {
            let _ = fs::File::create(note_file_path)?;
        }
    }

    if note_file_path.exists() {
        println!("\n---------");
        println!("  Remember to install the certificate \"_certs/root.crt.crt\" as root CA to your OS or browser.");
        println!("  ... If done, delete or rename \"_certs/NEED_TO_INSTALL_ROOT_CA\" to hide this message.");
        println!("---------\n");
    }

    Ok(())
}


fn start_proxy_server(el: &mut EventLoop) -> usize {
    let mut listen_count = 0;
    let global_config = crate::global::get_global_config();

    if global_config.core.inbound_http_enable {
        let http_server_addr = &global_config.core.inbound_http_listen; // "0.0.0.0:7890";
        match http_server_addr.parse() {
            Ok(addr) => {
                let result = proxy_http::HttpProxyServer::new(addr);
                if result.is_ok() {
                    let http_server = result.unwrap();
                    match http_server.initial_register(el) {
                        Ok(_) => {
                            wd_log::log_info_ln!("HTTP proxy server started on {}", http_server_addr);
                            listen_count += 1;
                        }
                        Err(e) => {
                            println!("Http proxy server fail to listen on {} {:?}", http_server_addr, e);
                        }
                    }
                } else {
                    println!("Fail to create http proxy server.");
                }
            }
            Err(e) => {
                println!("Fail to create http proxy server.\n{:?}", e);
            }
        }
    }

    if listen_count == 0 {
        println!("WARNING: NO ANY PROXY SERVER RUNNING!");
    }
    listen_count
}

