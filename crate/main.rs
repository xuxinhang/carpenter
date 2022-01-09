pub mod event_loop;
pub mod proxy_http;
pub mod http_header_parser;

use event_loop::EventLoop;
// use http_header_parser::parse_http_header;


fn main() {
    print!("Hello, mio!");
    // let mut resp_content = String::new();
    // resp_content.push_str("CONNECT 163.com HTTP/1.1\r\ncontent-type: application/json\r\ncontent-length: 15\r\n\r\n{\"hello\": null} ");
    // let (_, headers) = parse_http_header(resp_content.as_bytes()).unwrap();
    // println!("{:?}", headers);

    let mut el = EventLoop::new(1024).unwrap();
    start_proxy_server(&mut el);
    match el.start_loop() {
        Ok(()) => {
            print!("Event loop ends.");
        }
        Err(e) => {
            println!("Event lopp error\n{:?}", e);
        }
    }
}

fn start_proxy_server(el: &mut EventLoop) {
    let http_server_addr = "0.0.0.0:7890";

    match http_server_addr.parse() {
        Ok(addr) => {
            let result = proxy_http::HttpProxyServer::new(addr);
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
