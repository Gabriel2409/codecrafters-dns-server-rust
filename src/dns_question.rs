use std::io::{BufRead, Read};

use crate::dns_class::QClass;
use crate::dns_label::DnsLabel;
use crate::dns_type::QType;

use crate::{Error, Result};

#[derive(Debug, PartialEq)]
pub struct DnsQuestion {
    pub q_name: Vec<DnsLabel>,
    pub q_type: QType,
    pub q_class: QClass,
}

impl TryFrom<&mut dyn Read> for DnsQuestion {
    type Error = Error;

    fn try_from(reader: &mut dyn Read) -> Result<Self> {
        let mut one_byte_buf = [0u8; 1];
        let mut q_name = Vec::new();
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
            q_name.push(DnsLabel { length, label });
        }
        let mut two_byte_buf = [0u8; 2];
        reader.read_exact(&mut two_byte_buf)?;
        let q_type_val = u16::from_be_bytes(two_byte_buf);
        let q_type = QType::try_from(q_type_val)?;

        reader.read_exact(&mut two_byte_buf)?;
        let q_class_val = u16::from_be_bytes(two_byte_buf);
        let q_class = QClass::try_from(q_class_val)?;

        Ok(DnsQuestion {
            q_name,
            q_type,
            q_class,
        })
    }
}

impl From<DnsQuestion> for Vec<u8> {
    fn from(dns_question: DnsQuestion) -> Vec<u8> {
        let mut bytes = Vec::new();

        for dns_label in dns_question.q_name {
            bytes.push(dns_label.length);
            bytes.extend(dns_label.label.as_bytes());
        }
        bytes.push(0);
        let q_type: u16 = dns_question.q_type.into();
        bytes.extend(q_type.to_be_bytes());
        let q_class: u16 = dns_question.q_class.into();
        bytes.extend(q_class.to_be_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use super::*;

    #[test]
    fn test_dns_question_from_bytes() -> Result<()> {
        let domain_name = "query.example.com";

        let mut bytes = Vec::new();
        for s in domain_name.split(|x| x == '.') {
            bytes.push(s.len() as u8);
            bytes.extend(s.as_bytes());
        }
        bytes.push(0);

        bytes.extend([0b0, 0b00000111]);
        bytes.extend([0b0, 0b00000100]);

        let mut reader = Cursor::new(&bytes[..]);
        let reader_ref: &mut dyn Read = &mut reader;

        let dns_question: DnsQuestion = DnsQuestion::try_from(reader_ref)?;

        assert_eq!(
            dns_question,
            DnsQuestion {
                q_name: vec![
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
                q_type: QType::Mb,
                q_class: QClass::Hs
            }
        );
        let reconstructed_bytes: Vec<u8> = dns_question.into();
        assert_eq!(reconstructed_bytes, bytes);

        Ok(())
    }
}
