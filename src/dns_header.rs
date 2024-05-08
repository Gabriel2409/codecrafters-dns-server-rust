use crate::{Error, Result};

#[derive(Debug, PartialEq, Clone)]
/// Header section format
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1
pub struct DnsHeader {
    /// (ID) Random ID assigned to query packets. Response packets reply with same id
    pub packet_id: u16,
    /// third and fourth bytes contain multiple fields
    pub third_byte: DnsHeaderThirdByte,
    pub fourth_byte: DnsHeaderFourthByte,
    /// (QDCOUNT) Number of questions in the Question section.
    pub question_count: u16,
    /// (ANCOUNT) Number of records in the Answer section.
    pub answer_record_count: u16,
    /// (NSCOUNT) Number of records in the Authority section.
    pub authority_record_count: u16,
    /// (ARCOUNT) Number of records in the Additional section.
    pub additional_record_count: u16,
}
impl TryFrom<&[u8]> for DnsHeader {
    type Error = Error;

    fn try_from(bytes_slice: &[u8]) -> Result<Self> {
        if bytes_slice.len() != 12 {
            anyhow::bail!("Dns header should be 12 bytes_slice long");
        }
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes_slice[0..2]);
        let packet_id = u16::from_be_bytes(buf);

        let third_byte = DnsHeaderThirdByte::from(bytes_slice[2]);
        let fourth_byte = DnsHeaderFourthByte::from(bytes_slice[3]);

        buf.copy_from_slice(&bytes_slice[4..6]);
        let question_count = u16::from_be_bytes(buf);

        buf.copy_from_slice(&bytes_slice[6..8]);
        let answer_record_count = u16::from_be_bytes(buf);

        buf.copy_from_slice(&bytes_slice[8..10]);
        let authority_record_count = u16::from_be_bytes(buf);

        buf.copy_from_slice(&bytes_slice[10..12]);
        let additional_record_count = u16::from_be_bytes(buf);

        Ok(DnsHeader {
            packet_id,
            third_byte,
            fourth_byte,
            question_count,
            answer_record_count,
            authority_record_count,
            additional_record_count,
        })
    }
}

impl From<DnsHeader> for [u8; 12] {
    fn from(dns_header: DnsHeader) -> Self {
        let mut buf = [0u8; 12];
        buf[0..2].copy_from_slice(&dns_header.packet_id.to_be_bytes());
        buf[2] = dns_header.third_byte.into();
        buf[3] = dns_header.fourth_byte.into();
        buf[4..6].copy_from_slice(&dns_header.question_count.to_be_bytes());
        buf[6..8].copy_from_slice(&dns_header.answer_record_count.to_be_bytes());
        buf[8..10].copy_from_slice(&dns_header.authority_record_count.to_be_bytes());
        buf[10..12].copy_from_slice(&dns_header.additional_record_count.to_be_bytes());
        buf
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DnsHeaderThirdByte {
    pub query_response_ind: bool,
    /// (OPCODE) Specifies the kind of query in a message (4bits)
    pub operation_code: OpCode,
    /// (AA) 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    pub authoritative_answer: bool,
    /// (TC) 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    pub truncation: bool,
    /// (RD) Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    pub recursion_desired: bool,
}

impl From<u8> for DnsHeaderThirdByte {
    fn from(value: u8) -> Self {
        let query_response_ind = (value >> 7) == 1;
        let operation_code_val = (value & 0b0111_1000) >> 3;

        let operation_code = match operation_code_val {
            0 => OpCode::Query,
            1 => OpCode::Iquery,
            2 => OpCode::Status,
            3..=15 => OpCode::Reserved,
            _ => unreachable!(),
        };

        let authoritative_answer = ((value & 0b100) >> 2) == 1;
        let truncation = ((value & 0b10) >> 1) == 1;
        let recursion_desired = (value & 1) == 1;
        Self {
            query_response_ind,
            operation_code,
            authoritative_answer,
            truncation,
            recursion_desired,
        }
    }
}

impl From<DnsHeaderThirdByte> for u8 {
    fn from(dns_header_third_byte: DnsHeaderThirdByte) -> Self {
        let mut value = 0;
        if dns_header_third_byte.query_response_ind {
            value += 1 << 7;
        }

        let opcode_val = match dns_header_third_byte.operation_code {
            OpCode::Query => 0,
            OpCode::Iquery => 1,
            OpCode::Status => 2,
            OpCode::Reserved => 3,
        };

        value += opcode_val << 3;
        if dns_header_third_byte.authoritative_answer {
            value += 1 << 2;
        }
        if dns_header_third_byte.truncation {
            value += 1 << 1;
        }
        if dns_header_third_byte.recursion_desired {
            value += 1;
        }
        value
    }
}

// A four bit field that specifies kind of query in this message.
// This value is set by the originator of a query and copied into the response.
#[derive(Debug, PartialEq, Clone)]
pub enum OpCode {
    /// 0: a standard query (QUERY)
    Query,
    /// 1: an inverse query (IQUERY)
    Iquery,
    /// 2:  a server status request (STATUS)
    Status,
    /// 3-15 reserved for future use;
    Reserved,
}

#[derive(Debug, PartialEq, Clone)]
pub struct DnsHeaderFourthByte {
    /// (RA) Server sets this to 1 to indicate that recursion is available.
    pub recursion_available: bool,
    /// (Z) Used by DNSSEC queries. At inception, it was reserved for future use. (3 bits)
    pub reserved: u8,
    /// (RCODE)  Response code indicating the status of the response (4 bits)
    pub response_code: RCode,
}

impl From<u8> for DnsHeaderFourthByte {
    fn from(value: u8) -> Self {
        let recursion_available = (value >> 7) == 1;
        let reserved = (value & 0b0111_0000) >> 4;
        let response_code_val = value & 0b1111;
        let response_code = match response_code_val {
            0 => RCode::NoError,
            1 => RCode::FormatError,
            2 => RCode::ServerFailure,
            3 => RCode::NameError,
            4 => RCode::NotImplemented,
            5 => RCode::Refused,
            6..=15 => RCode::Reserved,
            _ => unreachable!(),
        };
        Self {
            recursion_available,
            reserved,
            response_code,
        }
    }
}

impl From<DnsHeaderFourthByte> for u8 {
    fn from(dns_header_fourth_byte: DnsHeaderFourthByte) -> Self {
        let mut value = 0;
        if dns_header_fourth_byte.recursion_available {
            value += 1 << 7;
        }
        value += dns_header_fourth_byte.reserved << 4;
        let rcode_val = match dns_header_fourth_byte.response_code {
            RCode::NoError => 0,
            RCode::FormatError => 1,
            RCode::ServerFailure => 2,
            RCode::NameError => 3,
            RCode::NotImplemented => 4,
            RCode::Refused => 5,
            RCode::Reserved => 6,
        };

        value += rcode_val;
        value
    }
}

/// 4 bit field set as part of the responses
#[derive(Debug, PartialEq, Clone)]
pub enum RCode {
    /// 0: No error condition
    NoError,
    /// 1: Format Error - unable to interpret query
    FormatError,
    /// 2: Server failure - problem with the name server
    ServerFailure,
    /// 3 : Name Error - domain name referenced in the query does not exist.
    NameError,
    /// 4: Not implemented - the name server does not support the requested kind of query.
    NotImplemented,
    /// 5: Refused - The name server refuses to perform the specified operation for policy reasons
    Refused,
    /// 6-15: Reserved for future use
    Reserved,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_header_from_bytes() -> Result<()> {
        let bytes: [u8; 12] = [
            0b1011, 0b1101, 0b00001100, 0b10100010, 0b11, 0b10101010, 0b0, 0b11011, 0b1101, 0b111,
            0b11111111, 0b11111111,
        ];

        let dns_header: DnsHeader = DnsHeader::try_from(&bytes[..])?;

        let expected_third_byte = DnsHeaderThirdByte {
            query_response_ind: false,
            operation_code: OpCode::Iquery,
            authoritative_answer: true,
            truncation: false,
            recursion_desired: false,
        };
        let expected_fourth_byte = DnsHeaderFourthByte {
            recursion_available: true,
            reserved: 0b010,
            response_code: RCode::ServerFailure,
        };

        assert_eq!(
            dns_header,
            DnsHeader {
                packet_id: 0b101100001101,
                third_byte: expected_third_byte,
                fourth_byte: expected_fourth_byte,
                question_count: 0b1110101010,
                answer_record_count: 0b11011,
                authority_record_count: 0b110100000111,
                additional_record_count: 0b1111111111111111,
            }
        );
        let reconstructed_bytes: [u8; 12] = dns_header.into();
        assert_eq!(reconstructed_bytes, bytes);

        Ok(())
    }
}
