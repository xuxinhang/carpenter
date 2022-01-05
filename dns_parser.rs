// A Simple DNS Server

use std::collections::HashMap;


pub enum QueryType {
    UNDEF,
    A,
}

#[derive(Debug)]
pub struct PacketQuestion {
    pub name: usize,
    pub typ: u16,
    pub class: u16,
}

#[derive(Debug)]
pub struct PacketAnswer {
    pub name: usize,
    pub typ: u16,
    pub class: u16,
    pub ttl: u32,
    pub len: u16,
    pub ip: u32,
}

#[derive(Debug)]
pub struct Packet {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: u8,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,

    pub labelseqs: HashMap<usize, String>,
    pub questions: Vec<PacketQuestion>,
    pub answers: Vec<PacketAnswer>,
}

impl Packet {
    pub fn new() -> Packet {
        Packet {
            id: 0,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: true,
            ra: true,
            z: 0,
            rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,

            labelseqs: HashMap::new(),
            questions: Vec::new(),
            answers: Vec::new(),
        }
    }

    pub fn from_buffer(buf: &[u8]) -> Result<Packet, ParserError> {
        let mut pkt = Packet::new();
        parse_packet(&mut pkt, buf)?;
        Ok(pkt)
    }
}


#[derive(Debug)]
pub enum ParserError {
    EarlyEnding,
    NotImplementedSyntax,
    WrongSyntax,
}

struct PacketParserRunner<'a> {
    ptr: usize,
    buf: &'a [u8],
}

impl PacketParserRunner<'_> {
    fn get(&mut self) -> Result<u8, ParserError> {
        if self.ptr >= self.buf.len() {
            return Err(ParserError::EarlyEnding);
        }
        let res = self.buf[self.ptr] as u8;
        self.ptr += 1;
        Ok(res)
    }

    fn get_u16(&mut self) -> Result<u16, ParserError> {
        let a = self.get()?;
        let b = self.get()?;
        let res = ((a as u16) << 8) | (b as u16);
        Ok(res)
    }

    fn seek(&mut self, next_ptr: usize) {
        self.ptr = next_ptr;
    }
}


fn parse_packet(pkt: &mut Packet, buf: &[u8]) -> Result<(), ParserError> {
    // reader
    let mut r = PacketParserRunner { ptr: 0, buf };

    // parse header
    pkt.id = r.get_u16()?;
    let a = r.get()?;
    let b = r.get()?;
    pkt.qr = (a & (1 << 7)) > 0;
    pkt.opcode = (a >> 3) & 0xf;
    pkt.aa = (a & (1 << 2)) > 0;
    pkt.tc = (a & (1 << 1)) > 0;
    pkt.rd = (a & (1 << 0)) > 0;
    pkt.ra = (b & (1 << 7)) > 0;
    pkt.z = (b >> 4) & 0x7;
    pkt.rcode = b & 0xf;
    let qdcount = r.get_u16()?;
    let ancount = r.get_u16()?;
    let nscount = r.get_u16()?;
    let arcount = r.get_u16()?;
    pkt.qdcount = qdcount;
    pkt.ancount = ancount;
    pkt.nscount = nscount;
    pkt.arcount = arcount;

    // parse questions
    let mut j = 0;
    while j < qdcount {
        // name label
        let mut back_pos = 0;
        let name = loop {
            let prefix = r.get_u16()?;
            if (prefix >> 14) == 0x3 {
                if back_pos <= 0 {
                    back_pos = r.ptr;
                }
                r.seek((prefix as usize) & 0x3fff);
                continue;
            }

            r.seek(r.ptr - 2);
            let label_pos = r.ptr;
            if pkt.labelseqs.get(&label_pos) == None {
                let mut created_label = String::new();
                loop {
                    let label_length = r.get()? as usize;
                    if label_length == 0 { break; }
                    let slice = &r.buf[(r.ptr)..(r.ptr + label_length)];
                    created_label.push_str(std::str::from_utf8(slice).unwrap());
                    created_label.push('.');
                    r.seek(r.ptr + label_length);
                }
                pkt.labelseqs.insert(label_pos, created_label);
            }
            if back_pos <= 0 { } else { r.seek(back_pos); }
            break label_pos;
        };

        // type
        let typ = r.get_u16()?;
        let class = r.get_u16()?;
        pkt.questions.push(PacketQuestion { name, typ, class });
        j += 1;
    }

    Ok(())
}
