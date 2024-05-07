#[derive(Debug, PartialEq, Clone)]
pub struct DnsLabel {
    pub length: u8,
    pub label: String,
}
