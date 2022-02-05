pub mod event_loop;
pub mod proxy_http;
pub mod http_header_parser;
pub mod transformer;
pub mod configuration;

use event_loop::EventLoop;
use std::rc::Rc;
use configuration::{GlobalConfiguration, load_default_configuration};
// use http_header_parser::parse_http_header;

// trait Plotter {
//     fn load(&mut self, source: Box<dyn std::io::Read>);
//     fn plot(&self);
// }

// struct Scatter {
//     data: Vec<u8>,
// }

// impl Plotter for Scatter {
//     fn load(&mut self, source: Box<dyn std::io::Read>) {
//         let mut data = vec![0; 256];
//         source.read(&mut self.data);
//     }
//     fn plot(&self) {
//         print!("Plotting...");
//     }
// }

fn main() {
    // let sca: Box<dyn Plotter> = Box::new(Scatter { data: vec![0; 100] });
// }

// fn main2() {
    print!("Hello, mio!");
    // let mut resp_content = String::new();
    // resp_content.push_str("CONNECT 163.com HTTP/1.1\r\ncontent-type: application/json\r\ncontent-length: 15\r\n\r\n{\"hello\": null} ");
    // let (_, headers) = parse_http_header(resp_content.as_bytes()).unwrap();
    // println!("{:?}", headers);

    print!("Loading config");
    let conf = Rc::new(load_default_configuration());

    let mut el = EventLoop::new(1024).unwrap();
    start_proxy_server(&mut el, conf);
    match el.start_loop() {
        Ok(()) => {
            print!("Event loop ends.");
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
                match el.register(Box::new(http_server)) {
                    Ok(_) => {
                        println!("Http proxy server started on {}", http_server_addr);
                    }
                    Err(e) => {
                        println!("Http proxy server fail to listen on {}", http_server_addr);
                        println!("{:?}", e);
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
