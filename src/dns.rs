use crate::Result;

#[derive(Debug, PartialEq)]
/// Header section format
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1
pub struct DnsHeader {
    /// (ID) Random ID assigned to query packets. Response packets reply with same id
    pub packet_id: u16,
    /// (QR) 1 for reply packet, 0 for question packet
    pub query_response_ind: bool,
    /// (OPCODE) Specifies the kind of query in a message (4bits)
    pub operation_code: OpCode,
    /// (AA) 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    pub authoritative_answer: bool,
    /// (TC) 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    pub truncation: bool,
    /// (RD) Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    pub recursion_desired: bool,
    /// (RA) Server sets this to 1 to indicate that recursion is available.
    pub recursion_available: bool,
    /// (Z) Used by DNSSEC queries. At inception, it was reserved for future use. (3 bits)
    pub reserved: u8,
    /// (RCODE)  Response code indicating the status of the response (4 bits)
    pub response_code: RCode,
    /// (QDCOUNT) Number of questions in the Question section.
    pub question_count: u16,
    /// (ANCOUNT) Number of records in the Answer section.
    pub answer_record_count: u16,
    /// (NSCOUNT) Number of records in the Authority section.
    pub authority_record_count: u16,
    /// (ARCOUNT) Number of records in the Additional section.
    pub additional_record_count: u16,
}

impl DnsHeader {
    /// Converts bytes into a dns_header
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 12 {
            anyhow::bail!("Dns header should be 12 bytes long");
        }
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[0..2]);
        let packet_id = u16::from_be_bytes(buf);

        let third_byte = bytes[2];
        let query_response_ind = (third_byte >> 7) == 1;
        let operation_code = OpCode::from_byte((third_byte & 0b0111_1000) >> 3)?;
        let authoritative_answer = ((third_byte & 0b100) >> 2) == 1;
        let truncation = ((third_byte & 0b10) >> 1) == 1;
        let recursion_desired = (third_byte & 1) == 1;

        let fourth_byte = bytes[3];
        let recursion_available = (fourth_byte >> 7) == 1;
        let reserved = (fourth_byte & 0b0111_0000) >> 4;
        let response_code = RCode::from_byte(fourth_byte & 0b1111)?;

        buf.copy_from_slice(&bytes[4..6]);
        let question_count = u16::from_be_bytes(buf);

        buf.copy_from_slice(&bytes[6..8]);
        let answer_record_count = u16::from_be_bytes(buf);

        buf.copy_from_slice(&bytes[8..10]);
        let authority_record_count = u16::from_be_bytes(buf);

        buf.copy_from_slice(&bytes[10..12]);
        let additional_record_count = u16::from_be_bytes(buf);

        Ok(DnsHeader {
            packet_id,
            query_response_ind,
            operation_code,
            authoritative_answer,
            truncation,
            recursion_desired,
            recursion_available,
            reserved,
            response_code,
            question_count,
            answer_record_count,
            authority_record_count,
            additional_record_count,
        })
    }
    /// Converts a dns_header back into bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend(self.packet_id.to_be_bytes());

        let mut third_byte = 0;
        if self.query_response_ind {
            third_byte += 1 << 7;
        }
        let opcode_val = self.operation_code.to_u8();
        third_byte += opcode_val << 3;
        if self.authoritative_answer {
            third_byte += 1 << 2;
        }
        if self.truncation {
            third_byte += 1 << 1;
        }
        if self.recursion_desired {
            third_byte += 1;
        }

        header.push(third_byte);

        let mut fourth_byte = 0;
        if self.recursion_available {
            fourth_byte += 1 << 7;
        }
        fourth_byte += self.reserved << 4;
        let rcode_val = self.response_code.to_u8();
        fourth_byte += rcode_val;

        header.push(fourth_byte);

        header.extend(self.question_count.to_be_bytes());
        header.extend(self.answer_record_count.to_be_bytes());
        header.extend(self.authority_record_count.to_be_bytes());
        header.extend(self.additional_record_count.to_be_bytes());

        header
    }
}

// A four bit field that specifies kind of query in this message.
// This value is set by the originator of a query and copied into the response.
#[derive(Debug, PartialEq)]
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

impl OpCode {
    /// maps a byte to an OpCode
    pub fn from_byte(byte: u8) -> Result<Self> {
        let op_code = match byte {
            0 => OpCode::Query,
            1 => OpCode::Iquery,
            2 => OpCode::Status,
            3..=15 => OpCode::Reserved,
            _ => anyhow::bail!("OPCODE should be 4 bits long"),
        };
        Ok(op_code)
    }
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Query => 0,
            Self::Iquery => 1,
            Self::Status => 2,
            Self::Reserved => 3,
        }
    }
}

/// 4 bit field set as part of the responses
#[derive(Debug, PartialEq)]
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

impl RCode {
    /// maps a byte to an OpCode
    pub fn from_byte(byte: u8) -> Result<Self> {
        let r_code = match byte {
            0 => RCode::NoError,
            1 => RCode::FormatError,
            2 => RCode::ServerFailure,
            3 => RCode::NameError,
            4 => RCode::NotImplemented,
            5 => RCode::Refused,
            6..=15 => RCode::Reserved,
            _ => anyhow::bail!("RCODE should be 4 bits long"),
        };
        Ok(r_code)
    }
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormatError => 1,
            Self::ServerFailure => 2,
            Self::NameError => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5,
            Self::Reserved => 6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_header_from_bytes() -> Result<()> {
        let bytes = [
            0b1011, 0b1101, 0b00001100, 0b10100010, 0b11, 0b10101010, 0b0, 0b11011, 0b1101, 0b111,
            0b11111111, 0b11111111,
        ];

        let dns_header = DnsHeader::from_bytes(&bytes)?;

        assert_eq!(
            dns_header,
            DnsHeader {
                packet_id: 0b101100001101,
                query_response_ind: false,
                operation_code: OpCode::Iquery,
                authoritative_answer: true,
                truncation: false,
                recursion_desired: false,
                recursion_available: true,
                reserved: 0b010,
                response_code: RCode::ServerFailure,
                question_count: 0b1110101010,
                answer_record_count: 0b11011,
                authority_record_count: 0b110100000111,
                additional_record_count: 0b1111111111111111,
            }
        );
        assert_eq!(dns_header.to_bytes(), bytes);

        Ok(())
    }
}
