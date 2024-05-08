use std::{
    io::{Cursor, Read},
    net::UdpSocket,
};
mod dns;
mod dns_answer;
mod dns_class;
mod dns_header;
mod dns_label;
mod dns_question;
mod dns_type;
mod error;

pub use error::{Error, Result};

use dns::{DnsReply, DnsRequest};

fn main() -> Result<()> {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        // receives data and fill the buffer
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let dns_req = DnsRequest::try_from(&buf[..size])?;
                let dns_rep = DnsReply::try_from(dns_req)?;
                let response: Vec<u8> = dns_rep.into();

                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
    Ok(())
}
