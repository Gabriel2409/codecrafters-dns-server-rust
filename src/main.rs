use std::net::{SocketAddr, UdpSocket};
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
    let mut should_forward = false;
    let args: Vec<String> = std::env::args().collect();

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");

    let udp_socket_forwarder =
        UdpSocket::bind("127.0.0.1:2054").expect("Failed to bind to address");

    if args.len() == 3 && args[1] == "--resolver".to_string() {
        should_forward = true;
        let server_to_forward_to = args[2].to_string();
        let server = server_to_forward_to.parse::<SocketAddr>()?;
        udp_socket_forwarder.connect(server)?;
    }

    let mut buf = [0; 512];

    loop {
        // receives data and fill the buffer
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let dns_request = DnsRequest::try_from(&buf[..size])?;
                dbg!(&dns_request);
                let response = match should_forward {
                    false => {
                        let dns_reply = DnsReply::try_from(dns_request)?;
                        let response: Vec<u8> = dns_reply.into();
                        response
                    }
                    true => {
                        let dns_requests = dns_request.split_questions();
                        let mut dns_replies = Vec::new();
                        for req in dns_requests {
                            let bytes: Vec<u8> = req.into();
                            let mut new_buf = [0; 512];

                            new_buf[..bytes.len()].copy_from_slice(&bytes);
                            udp_socket_forwarder.send(&new_buf)?;

                            let mut final_buf = [0; 512];
                            udp_socket_forwarder.recv(&mut final_buf)?;
                            let reply = DnsReply::try_from(&final_buf[..])?;

                            dns_replies.push(reply);
                        }
                        let final_reply = DnsReply::merge_replies(&dns_replies);
                        dbg!(&final_reply);
                        let response: Vec<u8> = final_reply.into();
                        response
                    }
                };

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
