// Simple DNS Server

use async_net::UdpSocket;
use crate::dns_parser::Packet;


pub trait MiniDnsServerHandler {
    fn handle(pkt: &Packet, raw: &[u8]) -> Packet;
}


pub struct MiniDnsServer<T: MiniDnsServerHandler> {
    handler: T,
    socket: Option<UdpSocket>,
}

impl<T: MiniDnsServerHandler> MiniDnsServer<T> {
    pub fn new(handler: T) -> MiniDnsServer<T> {
        MiniDnsServer::<T> { handler, socket: None }
    }

    pub async fn start(&mut self, addr: impl async_net::AsyncToSocketAddrs) -> Result<(), std::io::Error> {
        let socket = UdpSocket::bind(addr).await?;
        let mut buffer = vec![0u8; 2048];
        loop {
            println!("Hello A");
            let (n, addr) = socket.recv_from(&mut buffer).await?;
            let pkt_in = Packet::from_buffer(&buffer[..n]);
            println!("{:?}", pkt_in);
            println!("Hello B");
            socket.send_to(&buffer[..n], addr).await?;
            println!("Hello C");
        }
    }
}



