/// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
/// This is a superset of TYPE, but we will use it for both
/// queries and answers even though some of the values are specific to questions
use crate::{Error, Result};

#[derive(Debug, PartialEq)]
pub enum QType {
    /// 1 a host address
    A,
    /// 2 an authoritative name server
    Ns,
    /// 3 a mail destination (obsolete - use mx)
    Md,
    /// 4 a mail forwarder (obsolete - use mx)
    Mf,
    /// 5 the canonical name for an alias
    Cname,
    /// 6 marks the start of a zone of authority
    Soa,
    /// 7 a mailbox domain name (experimental)
    Mb,
    /// 8 a mail group member (experimental)
    Mg,
    /// 9 a mail rename domain name (experimental)
    Mr,
    /// 10 a null rr (experimental)
    Null,
    /// 11 a well known service description
    Wks,
    /// 12 a domain name pointer
    Ptr,
    /// 13 host information
    Hinfo,
    /// 14 mailbox or mail list information
    Minfo,
    /// 15 mail exchange
    Mx,
    /// 16 text strings
    Txt,
    /// 252 A request for a transfer of an entire zone
    Axfr,
    /// 253 A request for mailbox-related records (MB, MG or MR)
    Mailb,
    /// 254 A request for mail agent RRs (Obsolete - see MX)
    Maila,
    /// 255 A request for all records,
    StarSign,
}

impl TryFrom<u16> for QType {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        let q_type = match value {
            1 => Self::A,
            2 => Self::Ns,
            3 => Self::Md,
            4 => Self::Mf,
            5 => Self::Cname,
            6 => Self::Soa,
            7 => Self::Mb,
            8 => Self::Mg,
            9 => Self::Mr,
            10 => Self::Null,
            11 => Self::Wks,
            12 => Self::Ptr,
            13 => Self::Hinfo,
            14 => Self::Minfo,
            15 => Self::Mx,
            16 => Self::Txt,
            252 => Self::Axfr,
            253 => Self::Mailb,
            254 => Self::Maila,
            255 => Self::StarSign,
            _ => anyhow::bail!("Invalid QType"),
        };
        Ok(q_type)
    }
}

impl From<QType> for u16 {
    fn from(val: QType) -> Self {
        match val {
            QType::A => 1,
            QType::Ns => 2,
            QType::Md => 3,
            QType::Mf => 4,
            QType::Cname => 5,
            QType::Soa => 6,
            QType::Mb => 7,
            QType::Mg => 8,
            QType::Mr => 9,
            QType::Null => 10,
            QType::Wks => 11,
            QType::Ptr => 12,
            QType::Hinfo => 13,
            QType::Minfo => 14,
            QType::Mx => 15,
            QType::Txt => 16,
            QType::Axfr => 252,
            QType::Mailb => 253,
            QType::Maila => 254,
            QType::StarSign => 255,
        }
    }
}
