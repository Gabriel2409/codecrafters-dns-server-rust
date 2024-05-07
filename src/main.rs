use std::{
    io::{Cursor, Read},
    net::UdpSocket,
};
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

                let mut response = Vec::new();

                let mut reader = Cursor::new(&buf[..]);
                let mut header_buf = [0u8; 12];
                reader
                    .read_exact(&mut header_buf)
                    .expect("Could not fill header");

                // contains the header of the request
                let mut dns_header = DnsHeader::try_from(&header_buf[..])
                    .expect("unable to construct header from packet");

                // modifies certain fields for the response
                dns_header.third_byte.query_response_ind = true;
                dns_header.third_byte.authoritative_answer = false;
                dns_header.third_byte.truncation = false;

                let response_code = match dns_header.third_byte.operation_code {
                    OpCode::Query => RCode::NoError,
                    _ => RCode::NotImplemented,
                };

                dns_header.fourth_byte.recursion_available = false;
                dns_header.fourth_byte.reserved = 0;
                dns_header.fourth_byte.response_code = response_code;

                // dns_header.question_count = 1;
                // dns_header.answer_record_count = 1;

                let nb_questions = dns_header.question_count;
                dns_header.answer_record_count = nb_questions;
                dns_header.authority_record_count = 0;
                dns_header.additional_record_count = 0;

                let header_bytes: [u8; 12] = dns_header.into();
                response.extend(header_bytes);

                let mut questions = Vec::new();
                let mut answers = Vec::new();
                for _ in 0..nb_questions {
                    let mut dns_question =
                        DnsQuestion::try_from(&mut reader).expect("unable to construct question");

                    dns_question.q_type = QType::A;
                    dns_question.q_class = QClass::In;

                    let mut dns_answer = DnsAnswer::from(dns_question.clone());
                    dns_answer.ttl = 60;
                    dns_answer.rd_length = 4;
                    dns_answer.r_data = vec![45, 87, 98, 65];
                    questions.push(dns_question);
                    answers.push(dns_answer);
                }
                for dns_question in questions {
                    let question_bytes: Vec<u8> = dns_question.into();
                    response.extend(question_bytes);
                }
                for dns_answer in answers {
                    let answer_bytes: Vec<u8> = dns_answer.into();
                    response.extend(answer_bytes);
                }
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
