#[allow(unused_imports)]
use std::net::UdpSocket;

use codecrafters_dns_server::{DnsHeader, DnsPacketBuffer, MessageWriter, Question};

fn main() {
    println!("Logs from your program will appear here!");
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                dbg!(size);
                let mut parser = DnsPacketBuffer::new(&buf);
                let x = DnsHeader::parse(&mut parser).unwrap();
                dbg!(x);
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                let header = DnsHeader::response_with_id(id);
                let question = Question::new("codecrafters.io");
                let writer = MessageWriter::new(header, question);
                let mut out = [0u8; 512];
                match writer.write(&mut out) {
                    Ok(n) => {
                        udp_socket
                            .send_to(&out[..n], source)
                            .expect("Failed to send response");
                    }
                    Err(_) => {
                        eprintln!("Failed to write DNS message into buffer; response not sent");
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
