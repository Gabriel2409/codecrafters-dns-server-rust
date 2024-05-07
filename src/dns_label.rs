#[derive(Debug, PartialEq)]
pub struct DnsLabel {
    pub length: u8,
    pub label: String,
}
