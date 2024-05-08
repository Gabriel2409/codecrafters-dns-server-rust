use std::io::{Cursor, Read};

use crate::dns_header::{OpCode, RCode};
use crate::{dns_answer::DnsAnswer, dns_header::DnsHeader, dns_question::DnsQuestion};
use crate::{Error, Result};

#[derive(Debug)]
pub struct DnsRequest {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
}

impl DnsRequest {
    /// NOTE: all questions will have same packet id,
    /// not really tested
    pub fn split_questions(self) -> Vec<Self> {
        let mut dns_requests = Vec::new();
        for question in self.questions {
            let mut header = self.header.clone();
            header.question_count = 1;

            dns_requests.push(Self {
                header,
                questions: vec![question],
            });
        }
        dns_requests
    }
}

impl TryFrom<&[u8]> for DnsRequest {
    type Error = Error;

    fn try_from(buf: &[u8]) -> Result<Self> {
        let mut reader = Cursor::new(&buf[..]);
        let mut header_buf = [0u8; 12];
        reader
            .read_exact(&mut header_buf)
            .expect("Could not fill header");

        // contains the header of the request
        let header = DnsHeader::try_from(&header_buf[..])?;

        if header.third_byte.query_response_ind {
            anyhow::bail!("Header corresponds to a reply packet");
        }

        let mut questions = Vec::new();
        for _ in 0..header.question_count {
            let dns_question = DnsQuestion::try_from(&mut reader)?;
            questions.push(dns_question);
        }
        Ok(Self { header, questions })
    }
}

impl From<DnsRequest> for Vec<u8> {
    fn from(dns_request: DnsRequest) -> Self {
        let mut bytes = Vec::new();
        bytes.extend::<[u8; 12]>(dns_request.header.into());
        for question in dns_request.questions {
            bytes.extend::<Vec<u8>>(question.into());
        }
        bytes
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DnsReply {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
}

impl DnsReply {
    /// Hypothesis 1 answer per question,
    /// no error handling
    /// TODO: tests
    pub fn merge_replies(replies: &[Self]) -> Self {
        let mut header = replies[0].header.clone();
        header.question_count = replies.len() as u16;
        header.answer_record_count = replies.len() as u16;
        let mut questions = Vec::new();
        let mut answers = Vec::new();
        for dns_reply in replies {
            questions.extend(dns_reply.questions.clone());
            answers.extend(dns_reply.answers.clone());
        }
        Self {
            header,
            questions,
            answers,
        }
    }
}

impl TryFrom<&[u8]> for DnsReply {
    type Error = Error;

    fn try_from(buf: &[u8]) -> Result<Self> {
        let mut reader = Cursor::new(&buf[..]);
        let mut header_buf = [0u8; 12];
        reader
            .read_exact(&mut header_buf)
            .expect("Could not fill header");

        // contains the header of the reply
        let header = DnsHeader::try_from(&header_buf[..])?;

        if !header.third_byte.query_response_ind {
            anyhow::bail!("Header corresponds to a request packet");
        }

        let mut questions = Vec::new();
        for _ in 0..header.question_count {
            let dns_question = DnsQuestion::try_from(&mut reader)?;
            questions.push(dns_question);
        }
        let mut answers = Vec::new();
        for _ in 0..header.answer_record_count {
            let dns_answer = DnsAnswer::try_from(&mut reader)?;
            answers.push(dns_answer);
        }
        Ok(Self {
            header,
            questions,
            answers,
        })
    }
}
impl TryFrom<DnsRequest> for DnsReply {
    type Error = Error;

    /// Here we would actually fetch the records to answer the question
    fn try_from(dns_request: DnsRequest) -> Result<Self> {
        let mut header = dns_request.header;
        let questions = dns_request.questions;

        // // modifies certain fields for the response
        header.third_byte.query_response_ind = true;
        header.third_byte.authoritative_answer = false;
        header.third_byte.truncation = false;

        let response_code = match header.third_byte.operation_code {
            OpCode::Query => RCode::NoError,
            _ => RCode::NotImplemented,
        };

        header.fourth_byte.recursion_available = false;
        header.fourth_byte.reserved = 0;
        header.fourth_byte.response_code = response_code;
        //
        let nb_questions = header.question_count;
        header.answer_record_count = nb_questions;
        header.authority_record_count = 0;
        header.additional_record_count = 0;

        let mut answers = Vec::new();
        for question in questions.clone() {
            // question.q_type = QType::A;
            // question.q_class = QClass::In;

            let mut answer = DnsAnswer::from(question.clone());
            answer.ttl = 60;
            answer.rd_length = 4;
            answer.r_data = vec![45, 87, 98, 65];
            answers.push(answer);
        }
        Ok(Self {
            header,
            questions,
            answers,
        })
    }
}

impl From<DnsReply> for Vec<u8> {
    fn from(dns_reply: DnsReply) -> Self {
        let mut bytes = Vec::new();
        bytes.extend::<[u8; 12]>(dns_reply.header.into());
        for question in dns_reply.questions {
            bytes.extend::<Vec<u8>>(question.into());
        }
        for answer in dns_reply.answers {
            bytes.extend::<Vec<u8>>(answer.into());
        }
        bytes
    }
}
