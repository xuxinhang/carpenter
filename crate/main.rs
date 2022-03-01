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


use event_loop::EventLoop;
use std::rc::Rc;
use configuration::{GlobalConfiguration, load_default_configuration};


fn main() {
    wd_log::log_info_ln!("Hello, mio!");

    // intialize global static variables
    global::init_global_stuff();

    // load config from file
    wd_log::log_info_ln!("Loading config...");
    let conf = Rc::new(load_default_configuration());
    global::publish_global_config(conf.clone());

    // customize logger
    wd_log::set_level(wd_log::Level::from(conf.core.log_level));

    // start server and event loop
    let mut el = EventLoop::new(1024).unwrap();

    start_proxy_server(&mut el, conf);

    match el.start_loop() {
        Ok(()) => {
            println!("Event loop ends.");
        }
        Err(e) => {
            println!("Event lopp error\n{:?}", e);
        }
    }
}


fn start_proxy_server(el: &mut EventLoop, global_config: Rc<GlobalConfiguration>) -> usize {
    let mut listen_count = 0;

    if global_config.core.inbound_http_enable {
        let http_server_addr = &global_config.core.inbound_http_listen; // "0.0.0.0:7890";
        match http_server_addr.parse() {
            Ok(addr) => {
                let result = proxy_http::HttpProxyServer::new(addr, global_config.clone());
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
