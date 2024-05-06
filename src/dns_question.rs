use std::io::BufRead;

pub use crate::{Error, Result};

pub struct DnsQuestion {
    pub q_name: Vec<DnsLabel>,
    pub q_type: QType,
    pub q_class: QClass,
}

impl TryFrom<&mut dyn BufRead> for DnsQuestion {
    type Error = Error;

    fn try_from(reader: &mut dyn BufRead) -> Result<Self> {
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

pub struct DnsLabel {
    pub length: u8,
    pub label: String,
}

/// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
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

pub enum QClass {
    /// 1 the Internet
    In,
    ///2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    Cs,
    ///3 the CHAOS class
    Ch,
    ///4 Hesiod [Dyer 87]
    Hs,
    /// 255 any class
    StarSign,
}

impl TryFrom<u16> for QClass {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        let q_class = match value {
            1 => Self::In,
            2 => Self::Cs,
            3 => Self::Ch,
            4 => Self::Hs,
            255 => Self::StarSign,
            _ => anyhow::bail!("Invalid QClass"),
        };
        Ok(q_class)
    }
}

impl From<QClass> for u16 {
    fn from(val: QClass) -> Self {
        match val {
            QClass::In => 1,
            QClass::Cs => 2,
            QClass::Ch => 3,
            QClass::Hs => 4,
            QClass::StarSign => 255,
        }
    }
}
