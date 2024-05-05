use crate::Result;

#[derive(Debug)]
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

// A four bit field that specifies kind of query in this message.
// This value is set by the originator of a query and copied into the response.
#[derive(Debug)]
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
}

/// 4 bit field set as part of the responses
#[derive(Debug)]
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
}
