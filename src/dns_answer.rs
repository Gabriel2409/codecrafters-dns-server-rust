use std::io::Read;

use crate::dns_class::QClass;
use crate::dns_label::DnsLabel;
use crate::dns_question::DnsQuestion;
use crate::dns_type::QType;

use crate::{Error, Result};

#[derive(Debug, PartialEq)]
pub struct DnsAnswer {
    pub r_name: Vec<DnsLabel>,
    /// In reality, only a subset of QType
    pub r_type: QType,
    /// In reality, only a subset of QClass
    pub r_class: QClass,
    /// duration in seconds a record can be cached before requerying
    pub ttl: u32,
    /// length of the RDATA field in bytes
    pub rd_length: u16,
    /// Data specific to the record type.
    pub r_data: Vec<u8>,
}

impl TryFrom<&mut dyn Read> for DnsAnswer {
    type Error = Error;

    fn try_from(reader: &mut dyn Read) -> Result<Self> {
        let mut one_byte_buf = [0u8; 1];
        let mut r_name = Vec::new();
        loop {
            reader.read_exact(&mut one_byte_buf)?;
            let length = one_byte_buf[0];
            // null byte
            if length == 0 {
                break;
            }
            let mut content_buf = vec![0u8; length as usize];
            reader.read_exact(&mut content_buf)?;

            let label = String::from_utf8(content_buf)?;
            r_name.push(DnsLabel { length, label });
        }
        let mut two_byte_buf = [0u8; 2];
        reader.read_exact(&mut two_byte_buf)?;
        let r_type_val = u16::from_be_bytes(two_byte_buf);
        let r_type = QType::try_from(r_type_val)?;

        reader.read_exact(&mut two_byte_buf)?;
        let r_class_val = u16::from_be_bytes(two_byte_buf);
        let r_class = QClass::try_from(r_class_val)?;

        let mut four_byte_buf = [0u8; 4];

        reader.read_exact(&mut four_byte_buf)?;
        let ttl = u32::from_be_bytes(four_byte_buf);

        reader.read_exact(&mut two_byte_buf)?;
        let rd_length = u16::from_be_bytes(two_byte_buf);

        let mut r_data = vec![0u8; rd_length as usize];

        reader.read_exact(&mut r_data)?;

        Ok(DnsAnswer {
            r_name,
            r_type,
            r_class,
            ttl,
            rd_length,
            r_data,
        })
    }
}

impl From<DnsQuestion> for DnsAnswer {
    /// TODO: handle q_types and q_class not in type and class
    fn from(question: DnsQuestion) -> Self {
        DnsAnswer {
            r_name: question.q_name,
            r_type: question.q_type,
            r_class: question.q_class,
            ttl: 0,
            rd_length: 0,
            r_data: vec![],
        }
    }
}

impl From<DnsAnswer> for Vec<u8> {
    fn from(dns_answer: DnsAnswer) -> Vec<u8> {
        let mut bytes = Vec::new();

        for dns_label in dns_answer.r_name {
            bytes.push(dns_label.length);
            bytes.extend(dns_label.label.as_bytes());
        }
        bytes.push(0);
        let r_type: u16 = dns_answer.r_type.into();
        bytes.extend(r_type.to_be_bytes());
        let r_class: u16 = dns_answer.r_class.into();
        bytes.extend(r_class.to_be_bytes());

        bytes.extend(dns_answer.ttl.to_be_bytes());
        bytes.extend(dns_answer.rd_length.to_be_bytes());
        bytes.extend(dns_answer.r_data);

        bytes
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_dns_answer_from_bytes() -> Result<()> {
        let domain_name = "query.example.com";

        let mut bytes = Vec::new();
        for s in domain_name.split(|x| x == '.') {
            bytes.push(s.len() as u8);
            bytes.extend(s.as_bytes());
        }
        bytes.push(0);

        bytes.extend([0b0, 0b00000111]);
        bytes.extend([0b0, 0b00000100]);

        bytes.extend([0b0, 0b0, 0b101, 0b01110111]);
        bytes.extend([0b0, 0b100]);
        bytes.extend([7, 45, 32, 56]);

        let mut reader = Cursor::new(&bytes[..]);
        let reader_ref: &mut dyn Read = &mut reader;

        let dns_answer: DnsAnswer = DnsAnswer::try_from(reader_ref)?;

        assert_eq!(
            dns_answer,
            DnsAnswer {
                r_name: vec![
                    DnsLabel {
                        length: 5,
                        label: "query".to_string()
                    },
                    DnsLabel {
                        length: 7,
                        label: "example".to_string()
                    },
                    DnsLabel {
                        length: 3,
                        label: "com".to_string()
                    }
                ],
                r_type: QType::Mb,
                r_class: QClass::Hs,
                ttl: 0b10101110111,
                rd_length: 4,
                r_data: vec![7, 45, 32, 56]
            }
        );
        let reconstructed_bytes: Vec<u8> = dns_answer.into();
        assert_eq!(reconstructed_bytes, bytes);

        Ok(())
    }
}
