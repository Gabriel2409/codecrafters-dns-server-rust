use std::net::UdpSocket;
mod dns;
mod error;

pub use error::{Error, Result};

use crate::dns::{DnsHeader, RCode};

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        // receives data and fill the buffer
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                // get filled buffer with &mut buf[..size];
                println!("Received {} bytes from {}", size, source);

                // let mut pack_id_buf = [0u8; 2];
                // pack_id_buf.copy_from_slice(&buf[0..2]);
                // let packet_id = u16::from_be_bytes(pack_id_buf);
                //
                // let dns_header = DnsHeader {
                //     packet_id,
                //
                //     query_response_ind: true,
                //     operation_code: dns::OpCode::Query,
                //     authoritative_answer: false,
                //     truncation: false,
                //     recursion_desired: false,
                //     recursion_available: false,
                //     reserved: 0,
                //     response_code: RCode::NoError,
                //     question_count: 0,
                //     answer_record_count: 0,
                //     authority_record_count: 0,
                //     additional_record_count: 0,
                // };

                let response = [];
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
}
