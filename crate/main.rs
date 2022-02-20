pub mod event_loop;
pub mod proxy_http;
pub mod http_header_parser;
pub mod transformer;
pub mod configuration;
pub mod proxy_client;
pub mod common;
pub mod uri_match;

use event_loop::EventLoop;
use std::rc::Rc;
use configuration::{GlobalConfiguration, load_default_configuration};


fn main() {

    let mut tree = uri_match::TierTree::create_root();
    tree.insert(&mut String::from("*.z.cn").chars(), 0);
    tree.insert(&mut String::from("z*g.z.cn").chars(), 1);
    tree.insert(&mut String::from("bai.cc").chars(), 2);
    let search_result = tree.get(&mut String::from("zimg.z.cn").chars());
    println!("{:?}", search_result);

    wd_log::log_info_ln!("Hello, mio!");
    wd_log::log_info_ln!("Loading config");
    let conf = Rc::new(load_default_configuration());

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


fn start_proxy_server(el: &mut EventLoop, global_config: Rc<GlobalConfiguration>) {
    let http_server_addr = "0.0.0.0:7890";

    match http_server_addr.parse() {
        Ok(addr) => {
            let result = proxy_http::HttpProxyServer::new(addr, global_config);
            if result.is_ok() {
                let http_server = result.unwrap();
                match http_server.initial_register(el) {
                    Ok(_) => {
                        wd_log::log_info_ln!("HTTP proxy server started on {}", http_server_addr);
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
