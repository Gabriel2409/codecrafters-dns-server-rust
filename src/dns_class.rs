/// https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
/// This is a superset of CLASS, but we will use it for both
/// queries and answers even though some of the values are specific to questions
use crate::{Error, Result};

#[derive(Debug, PartialEq, Clone)]
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
