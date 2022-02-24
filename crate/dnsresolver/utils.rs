use std::net::{IpAddr};
use domain::base::{
    Dname, MessageBuilder, Rtype, StaticCompressor, StreamTarget, Message,
};


pub fn build_dns_query_message(name: &str) -> Result<Vec<u8>, ()> {
    let name = name.to_string();

    let mut msg = MessageBuilder::from_target(
        StaticCompressor::new(StreamTarget::new_vec())
    ).unwrap();

    let msg_header = msg.header_mut();
    msg_header.set_qr(false);
    msg_header.set_rd(true);

    let mut msg_question = msg.question();
    let dname = Dname::<Vec<u8>>::from_chars(name.chars()).or(Err(()))?;
    msg_question.push((&dname, Rtype::A)).or(Err(()))?;

    let target = msg_question.finish().into_target();
    Ok(target.as_dgram_slice().to_vec())
}

pub fn parse_dns_response_message(msg_bytes: &[u8]) -> Result<Option<IpAddr>, ()> {
    let msg = Message::from_octets(msg_bytes).or(Err(()))?;

    if msg.header_counts().ancount() == 0 {
        return Ok(None);
    }

    let mut selected_addr = None;

    for record in msg.answer().or(Err(()))? {
        if record.is_err() {
            continue;
        }
        // let record = record.unwrap().into_record().or(Err(()))?;
        let record = record.unwrap();
        // if record.is_none() {
        //     continue;
        // }
        // let record = record.unwrap();
        match record.rtype() {
            Rtype::A => {
                if let Ok(Some(r)) = record.into_record() {
                    let data: domain::rdata::rfc1035::A = r.into_data();
                    selected_addr = Some(IpAddr::V4(data.addr()));
                } else {
                    return Err(());
                }
            }
            // Rtype::Aaaa => {
            //     if let Ok(Some(r)) = record.into_record() {
            //         let data: domain::rdata::rfc3596::Aaaa = r.into_data();
            //         selected_addr = Some(data.addr());
            //     } else {
            //         return Err(());
            //     }
            // }
            _ => { continue; },
        }
        break;
    }

    Ok(selected_addr)
}
