use std::cell::RefCell;
use std::io;
use std::rc::Rc;

pub mod event_loop;
pub mod configuration;
pub mod common;
pub mod uri_match;
pub mod dnsresolver;
pub mod global;
pub mod utils;
pub mod certmgr;
pub mod authorization;
pub mod credential;
pub mod bridge;
pub mod stations;
pub mod listener;
pub mod helper;

use authorization::verifiers::{load_simple_credentials_from_file, AuthenticationVerifier, FreeAuthenticationVerifier};
use event_loop::EventLoop;
use listener::launch_server_listener;
use crate::certmgr::certstorage::{fetch_or_generate_tls_root_certificate, prepare_certificate_storage_filesystem_structure};

const _WELCOME_ART_1: &str = r"
     a88888b.                                                dP
    d8'   `88                                                88
    88        .d8888b. 88d888b. 88d888b. .d8888b. 88d888b. d8888P .d8888b. 88d888b.
    88        88'  `88 88'  `88 88'  `88 88ooood8 88'  `88   88   88ooood8 88'  `88
    Y8.   .88 88.  .88 88       88.  .88 88.  ... 88    88   88   88.  ... 88
     Y88888P' `88888P8 dP       88Y888P' `88888P' dP    dP   dP   `88888P' dP
                                88
                                dP
";

const WELCOME_ART_2: &str = r"
       ___                                   _
      / __\  __ _  _ __  _ __    ___  _ __  | |_   ___  _ __
     / /    / _` || '__|| '_ \  / _ \| '_ \ | __| / _ \| '__|
    / /___ | (_| || |   | |_) ||  __/| | | || |_ |  __/| |
    \____/  \__,_||_|   | .__/  \___||_| |_| \__| \___||_|
                        |_|
";


const SIMPLE_CREDENTIAL_FILE: &str = "./config/simple_credentials.txt";

fn main() {
    println!("{}", WELCOME_ART_2);
    println!("_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ ");

    // initialize global static variables
    global::init_global_stuff();

    // load config from files
    wd_log::log_info_ln!("Loading config...");
    let conf = Rc::new(configuration::load_default_configuration());
    global::publish_global_config(conf.clone());

    // customize logger
    wd_log::set_level(wd_log::Level::from(conf.core.log_level));

    // prepare root certificates
    prepare_certificate_storage_filesystem_structure();
    if let Err(e) = fetch_or_generate_tls_root_certificate() {
        wd_log::log_error_ln!("Fail to prepare certificates: {:?}", e);
        panic!();
    }

    if std::path::Path::new(certmgr::certstorage::ROOT_CA_FLAG_PATH).exists() {
        println!("\n---------");
        println!("  Remember to install the certificate \"_certificates/root_ca/root_ca.crt\" as root CA to your OS or browser.");
        println!("  ... If done, delete or rename \"_certs/NEED_TO_INSTALL_ROOT_CA\" to hide this message.");
        println!("---------\n");
    }

    // authentication infrastructure
    let res = create_default_authentication_storage();
    if let Err(e) = res {
        wd_log::log_error_ln!("Fail to create authentication manager: {:?}", e);
        panic!();
    }
    let authentication_manager = Rc::new(RefCell::new(res.unwrap()));

    // register server
    let mut el = EventLoop::new(1024).unwrap();
    let server_count = register_servers(&mut el, authentication_manager.clone());
    if server_count == 0 {
        wd_log::log_warn_ln!("No proxy server is running. Please check your configuration.");
    }

    // start event loop
    match el.start_loop() {
        Ok(_) => {
            wd_log::log_info_ln!("Event loop exited normally.");
        }
        Err(e) => {
            wd_log::log_error_ln!("Event loop exited with error: {:?}", e);
        }
    }
}


fn create_default_authentication_storage() -> io::Result<Box<dyn AuthenticationVerifier>> {
    let verifier = &global::get_global_config().core.authentication_verifier;
    match verifier {
        configuration::AuthenticationVerifierDescriptor::Free => {
            Ok(Box::new(FreeAuthenticationVerifier::new()))
        },
        configuration::AuthenticationVerifierDescriptor::Simple(_) => {
            use crate::authorization::verifiers::SimpleAuthenticationVerifier;
            let credentials = load_simple_credentials_from_file(SIMPLE_CREDENTIAL_FILE)?;
            let manager = SimpleAuthenticationVerifier::new(&credentials);
            Ok(Box::new(manager))
        }
    }
}


fn register_servers(el: &mut EventLoop, authentication_manager: Rc<RefCell<Box<dyn AuthenticationVerifier>>>) -> usize {
    let mut listen_count = 0;
    let global_config = global::get_global_config();
    let inbound_server_config = &global_config.core.inbound_server;

    for (key, cfg) in inbound_server_config.iter() {
        let listen_addr = cfg.addr;

        if let Err(e) = launch_server_listener(el, cfg, listen_addr, authentication_manager.clone()) {
            wd_log::log_error_ln!("Fail to launch generic incoming listener \"{}\": {:?}", key, e);
            continue;
        }

        listen_count += 1;
    }

    listen_count
}

