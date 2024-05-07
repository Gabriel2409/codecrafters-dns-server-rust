use std::net::UdpSocket;
mod dns_answer;
mod dns_class;
mod dns_header;
mod dns_label;
mod dns_question;
mod dns_type;
mod error;

pub use error::{Error, Result};

use dns_answer::DnsAnswer;
use dns_class::QClass;
use dns_header::{DnsHeader, DnsHeaderFourthByte, DnsHeaderThirdByte, OpCode, RCode};
use dns_label::DnsLabel;
use dns_question::DnsQuestion;
use dns_type::QType;

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

                let mut pack_id_buf = [0u8; 2];
                pack_id_buf.copy_from_slice(&buf[0..2]);
                let packet_id = u16::from_be_bytes(pack_id_buf);

                let dns_header = DnsHeader {
                    packet_id,
                    third_byte: DnsHeaderThirdByte {
                        query_response_ind: true,
                        operation_code: OpCode::Query,
                        authoritative_answer: false,
                        truncation: false,
                        recursion_desired: false,
                    },
                    fourth_byte: DnsHeaderFourthByte {
                        recursion_available: false,
                        reserved: 0,
                        response_code: RCode::NoError,
                    },
                    question_count: 1,
                    answer_record_count: 1,
                    authority_record_count: 0,
                    additional_record_count: 0,
                };

                let dns_question = DnsQuestion {
                    q_name: {
                        vec![
                            DnsLabel {
                                length: 12,
                                label: "codecrafters".to_string(),
                            },
                            DnsLabel {
                                length: 2,
                                label: "io".to_string(),
                            },
                        ]
                    },
                    q_type: QType::A,
                    q_class: QClass::In,
                };

                let dns_answer = DnsAnswer {
                    r_name: {
                        vec![
                            DnsLabel {
                                length: 12,
                                label: "codecrafters".to_string(),
                            },
                            DnsLabel {
                                length: 2,
                                label: "io".to_string(),
                            },
                        ]
                    },
                    r_type: QType::A,
                    r_class: QClass::In,
                    ttl: 60,
                    rd_length: 4,
                    r_data: vec![78, 45, 89, 26],
                };

                let mut response = Vec::new();
                let header_bytes: [u8; 12] = dns_header.into();
                response.extend(header_bytes);

                let question_bytes: Vec<u8> = dns_question.into();
                response.extend(question_bytes);

                let answer_bytes: Vec<u8> = dns_answer.into();
                response.extend(answer_bytes);

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
