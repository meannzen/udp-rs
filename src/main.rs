use std::env;
use std::net::UdpSocket;
use std::time::Duration;

use codecrafters_dns_server::{Answer, DnsHeader, MessageWriter, QClass, QType, Question};

fn read_u16_be(buf: &[u8], pos: usize) -> Option<u16> {
    if pos + 2 > buf.len() {
        None
    } else {
        Some(u16::from_be_bytes([buf[pos], buf[pos + 1]]))
    }
}

fn parse_name(packet: &[u8], start_pos: usize) -> Result<(String, usize), String> {
    if start_pos >= packet.len() {
        return Err("start_pos out of range".into());
    }

    let mut labels = Vec::new();
    let mut pos = start_pos;
    let mut jumped = false;
    let mut jump_pos = 0usize;
    let mut steps = 0usize;

    loop {
        if steps > 128 {
            return Err("too many label steps (possible loop)".into());
        }
        steps += 1;

        if pos >= packet.len() {
            return Err("out of range while parsing name".into());
        }

        let len = packet[pos];
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= packet.len() {
                return Err("pointer truncated".into());
            }
            let b2 = packet[pos + 1];
            let pointer = ((len as u16 & 0x3F) << 8) | (b2 as u16);
            let pointer = pointer as usize;
            if pointer >= packet.len() {
                return Err("pointer out of range".into());
            }
            if !jumped {
                jump_pos = pos + 2;
            }
            pos = pointer;
            jumped = true;
            continue;
        } else if len == 0 {
            pos += 1;
            break;
        } else {
            let len_usize = len as usize;
            if pos + 1 + len_usize > packet.len() {
                return Err("label extends past packet".into());
            }
            let label = &packet[pos + 1..pos + 1 + len_usize];
            match std::str::from_utf8(label) {
                Ok(s) => labels.push(s.to_string()),
                Err(_) => return Err("invalid UTF-8 in label".into()),
            }
            pos += 1 + len_usize;
        }
    }

    let name = labels.join(".");
    let next_pos = if jumped { jump_pos } else { pos };
    Ok((name, next_pos))
}

fn encode_name_to(vec: &mut Vec<u8>, name: &str) -> Result<(), String> {
    for label in name.split('.') {
        let len = label.len();
        if len == 0 {
            continue;
        }
        if len > 63 {
            return Err("label too long".into());
        }
        vec.push(len as u8);
        vec.extend_from_slice(label.as_bytes());
    }
    vec.push(0);
    Ok(())
}

fn qtype_from_u16(v: u16) -> Option<QType> {
    match v {
        1 => Some(QType::A),
        5 => Some(QType::CNAME),
        _ => None,
    }
}

fn qclass_from_u16(v: u16) -> Option<QClass> {
    match v {
        1 => Some(QClass::IN),
        2 => Some(QClass::CS),
        _ => None,
    }
}

fn build_one_question_query(
    id: u16,
    flags: u16,
    qname: &str,
    qtype: u16,
    qclass: u16,
) -> Result<Vec<u8>, String> {
    let mut v = Vec::with_capacity(512);
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&flags.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    v.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    v.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    v.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    encode_name_to(&mut v, qname)?;
    v.extend_from_slice(&qtype.to_be_bytes());
    v.extend_from_slice(&qclass.to_be_bytes());
    Ok(v)
}

fn parse_a_answers(packet: &[u8]) -> Result<Vec<[u8; 4]>, String> {
    if packet.len() < 12 {
        return Err("response too small".into());
    }
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;

    let mut pos = 12usize;

    // skip questions
    for _ in 0..qdcount {
        let (_, next_pos) = parse_name(packet, pos)?;
        pos = next_pos;
        if pos + 4 > packet.len() {
            return Err("truncated question".into());
        }
        pos += 4; // QTYPE + QCLASS
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        let (_name, next_pos) = parse_name(packet, pos)?;
        pos = next_pos;
        if pos + 10 > packet.len() {
            return Err("truncated answer header".into());
        }
        let typ = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let _class = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
        let _ttl = u32::from_be_bytes([
            packet[pos + 4],
            packet[pos + 5],
            packet[pos + 6],
            packet[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > packet.len() {
            return Err("truncated rdata".into());
        }
        if typ == 1 && rdlength == 4 {
            let ip = [
                packet[pos],
                packet[pos + 1],
                packet[pos + 2],
                packet[pos + 3],
            ];
            answers.push(ip);
        }
        pos += rdlength;
    }

    Ok(answers)
}

fn main() {
    let mut args = env::args().skip(1);
    let mut resolver_addr: Option<String> = None;
    while let Some(arg) = args.next() {
        if arg == "--resolver" {
            resolver_addr = args.next();
            break;
        }
    }
    let resolver_addr = match resolver_addr {
        Some(a) => a,
        None => {
            eprintln!(
                "Usage: {} --resolver <ip:port>",
                env::args().next().unwrap_or_default()
            );
            return;
        }
    };

    let socket = match UdpSocket::bind("127.0.0.1:2053") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to bind UDP socket: {}", e);
            return;
        }
    };

    let resolver_socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create resolver socket: {}", e);
            return;
        }
    };

    let _ = resolver_socket.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));

    println!(
        "Forwarding DNS server listening on 127.0.0.1:2053, resolver={}",
        resolver_addr
    );

    let mut buf = [0u8; 1500];
    loop {
        let (size, src) = match socket.recv_from(&mut buf) {
            Ok((s, a)) => (s, a),
            Err(e) => {
                eprintln!("recv_from error: {}", e);
                continue;
            }
        };
        let packet = &buf[..size];
        if packet.len() < 12 {
            eprintln!(
                "Received too-small packet from {} len={}",
                src,
                packet.len()
            );
            continue;
        }

        let id = u16::from_be_bytes([packet[0], packet[1]]);
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        let rd = ((flags >> 8) & 1) == 1;
        let opcode = ((flags >> 11) & 0xF) as u8;

        let qdcount = match read_u16_be(packet, 4) {
            Some(v) => v,
            None => {
                eprintln!("Malformed packet from {}: cannot read QDCOUNT", src);
                continue;
            }
        };
        if qdcount == 0 {
            eprintln!("No questions in packet from {}", src);
            continue;
        }

        // Parse all questions (supports compression)
        let mut questions: Vec<(String, u16, u16)> = Vec::new();
        let mut pos = 12usize;
        let mut ok = true;
        for _ in 0..(qdcount as usize) {
            match parse_name(packet, pos) {
                Ok((qname, next_pos)) => {
                    pos = next_pos;
                    if pos + 4 > packet.len() {
                        eprintln!("Packet from {} truncated while reading QTYPE/QCLASS", src);
                        ok = false;
                        break;
                    }
                    let qtype_u16 = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
                    let qclass_u16 = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
                    pos += 4;
                    questions.push((qname, qtype_u16, qclass_u16));
                }
                Err(e) => {
                    eprintln!("Failed to parse QNAME from {}: {}", src, e);
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            continue;
        }

        // For each question, forward exactly one-question query to resolver and collect answers.
        let mut collected_answers: Vec<Answer> = Vec::new();
        for (i, (qname, qtype_u16, qclass_u16)) in questions.iter().enumerate() {
            // Build a single-question query. Use the original packet's opcode and RD.
            // We'll use the same ID as the original request when forwarding, and do the queries sequentially.
            let mut forward_flags: u16 = 0;
            // QR = 0 (query)
            forward_flags |= ((opcode as u16) & 0xF) << 11;
            if rd {
                forward_flags |= 1 << 8;
            }

            let query_packet =
                match build_one_question_query(id, forward_flags, qname, *qtype_u16, *qclass_u16) {
                    Ok(q) => q,
                    Err(e) => {
                        eprintln!("Failed to build forward query for {}: {}", qname, e);
                        continue;
                    }
                };

            if let Err(e) = resolver_socket.send_to(&query_packet, &resolver_addr) {
                eprintln!("Failed to send query to resolver {}: {}", resolver_addr, e);
                continue;
            }

            // Receive response(s). The resolver is expected to reply for a single question.
            let mut resp_buf = [0u8; 1500];
            let (rsize, rsrc) = match resolver_socket.recv_from(&mut resp_buf) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Timeout/recv error from resolver {}: {}", resolver_addr, e);
                    continue;
                }
            };
            // optionally check rsrc == resolver_addr, but resolver_addr may resolve to multiple IPs; skip strict check.

            let resp_packet = &resp_buf[..rsize];
            // Parse A records from resolver response
            match parse_a_answers(resp_packet) {
                Ok(ips) => {
                    for ip in ips {
                        let answer = Answer::new(qname, ip, 60);
                        collected_answers.push(answer);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse answers from resolver response: {}", e);
                }
            }
        }

        // Build response header mirroring ID/opcode/RD and RCODE rule
        let header = DnsHeader::response_with_id_and_counts(
            id,
            opcode,
            rd,
            qdcount,
            collected_answers.len() as u16,
            0,
            0,
        );

        // Build questions vector (un-compressed) and answers vector
        let mut q_objs: Vec<Question> = Vec::with_capacity(questions.len());
        for (qname, qtype_u16, qclass_u16) in &questions {
            let qtype = qtype_from_u16(*qtype_u16).unwrap_or(QType::A);
            let qclass = qclass_from_u16(*qclass_u16).unwrap_or(QClass::IN);
            q_objs.push(Question::with_type_class(qname, qtype, qclass));
        }

        let writer = MessageWriter::new_with_sections(header, q_objs, collected_answers);

        match writer.to_vec() {
            Ok(resp) => {
                if let Err(e) = socket.send_to(&resp, src) {
                    eprintln!("Failed to send response to {}: {}", src, e);
                }
            }
            Err(e) => {
                eprintln!("Failed to serialize response: {:?}", e);
            }
        }
    }
}
