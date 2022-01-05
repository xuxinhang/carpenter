pub mod dns_parser;
pub mod dns_server;

use crate::dns_parser::{Packet};


struct EchoDnsServerHandler {}

impl dns_server::MiniDnsServerHandler for EchoDnsServerHandler {
    fn handle(pkt: &Packet, raw: &[u8]) -> Packet {
        Packet::new()
    }
}


fn main() {
    println!("Hello, Carpenter!");

    let testcase = vec![
        0x86, 0x2a, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
    ];

    match dns_parser::Packet::from_buffer(&testcase[..]) {
        Ok(p) => {
            println!("{:?}", p);
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }

    let server_handler = EchoDnsServerHandler {};
    let mut server = dns_server::MiniDnsServer::<EchoDnsServerHandler>::new(server_handler);
    let server_future = server.start("0.0.0.0:53");
    let _ = async_io::block_on(server_future);
}
