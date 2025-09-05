use anyhow::Result;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use trust_dns_proto::{
    op::{Header, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RecordType},
    serialize::binary::{BinDecodable, BinEncodable, BinEncoder},
};

/// Global query ID counter with atomic wraparound
static NEXT_ID: AtomicU16 = AtomicU16::new(1);

/// Sanitize a domain name for DNS queries
/// 
/// This function attempts to handle "dirty" domains that may not be RFC-compliant:
/// 1. First tries Name::from_ascii() for standard parsing
/// 2. If that fails, replaces invalid characters with hyphens
/// 3. Ensures the domain can be queried even if not perfectly formatted
pub fn sanitize_domain(domain: &str) -> Result<Name> {
    // First, try standard ASCII parsing
    if let Ok(name) = Name::from_ascii(domain) {
        return Ok(name);
    }
    
    // If that fails, sanitize by replacing invalid characters
    let mut sanitized = domain.to_string();
    
    // Replace invalid characters with hyphens
    // Keep only alphanumeric, dots, and hyphens
    sanitized = sanitized
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    
    // Remove leading/trailing dots and hyphens
    sanitized = sanitized.trim_matches(|c| c == '.' || c == '-').to_string();
    
    // Ensure we don't have empty labels
    if sanitized.is_empty() {
        sanitized = "invalid-domain".to_string();
    }
    
    // Try again with sanitized domain
    Name::from_ascii(&sanitized)
        .or_else(|_| {
            // Last resort: create a simple valid domain
            Name::from_ascii("sanitized-domain.invalid")
        })
        .map_err(|e| anyhow::anyhow!("Failed to sanitize domain '{}': {}", domain, e))
}

/// Get next query ID with atomic wraparound
pub fn next_query_id() -> u16 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}
/// DNS query packet builder and parser
#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub id: u16,
    pub domain: String,
    pub record_type: RecordType,
    pub resolver: SocketAddr,
}

impl DnsPacket {
    /// Create a new DNS packet with sequential ID
    pub fn new(domain: String, record_type: RecordType, resolver: SocketAddr) -> Self {
        let id = next_query_id();
        Self {
            id,
            domain,
            record_type,
            resolver,
        }
    }

    /// Build a DNS query packet using sanitized domain
    pub fn build_query(&self) -> Result<Bytes> {
        // Create header
        let mut header = Header::new();
        header.set_id(self.id);
        header.set_message_type(MessageType::Query);
        header.set_op_code(OpCode::Query);
        header.set_recursion_desired(true);

        // Sanitize and create query
        let name = sanitize_domain(&self.domain)?;
        let query = Query::query(name, self.record_type);

        // Create message
        let mut message = Message::new();
        message.set_header(header);
        message.add_query(query);

        // Encode to bytes
        let mut buffer = Vec::new();
        let mut encoder = BinEncoder::new(&mut buffer);
        message.emit(&mut encoder)?;

        Ok(Bytes::from(buffer))
    }

    /// Parse a DNS response packet
    pub fn parse_response(data: &[u8]) -> Result<DnsResponse> {
        let message = Message::from_bytes(data)?;
        
        let header = message.header();
        let id = header.id();
        let response_code = header.response_code();
        
        let mut answers = Vec::new();
        
        // Extract answers
        for answer in message.answers() {
            if let Some(rdata) = answer.data() {
                answers.push(DnsAnswer {
                    name: answer.name().to_string(),
                    record_type: answer.record_type(),
                    ttl: answer.ttl(),
                    data: format_rdata(rdata),
                });
            }
        }

        Ok(DnsResponse {
            id,
            response_code,
            answers,
        })
    }
}

/// DNS response structure
#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub id: u16,
    pub response_code: ResponseCode,
    pub answers: Vec<DnsAnswer>,
}

impl DnsResponse {
    /// Check if the response is successful
    pub fn is_success(&self) -> bool {
        self.response_code == ResponseCode::NoError && !self.answers.is_empty()
    }

    /// Get the first answer data if available
    pub fn first_answer(&self) -> Option<&str> {
        self.answers.first().map(|a| a.data.as_str())
    }
}

/// DNS answer record
#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: RecordType,
    pub ttl: u32,
    pub data: String,
}

/// Format resource record data for display
fn format_rdata(rdata: &trust_dns_proto::rr::RData) -> String {
    use trust_dns_proto::rr::RData;
    
    match rdata {
        RData::A(ip) => ip.to_string(),
        RData::AAAA(ip) => ip.to_string(),
        RData::CNAME(name) => name.to_string(),
        RData::MX(mx) => format!("{} {}", mx.preference(), mx.exchange()),
        RData::NS(name) => name.to_string(),
        RData::PTR(name) => name.to_string(),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            soa.mname(),
            soa.rname(),
            soa.serial(),
            soa.refresh(),
            soa.retry(),
            soa.expire(),
            soa.minimum()
        ),
        RData::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority(),
            srv.weight(),
            srv.port(),
            srv.target()
        ),
        RData::TXT(txt) => {
            txt.iter()
                .map(|s| String::from_utf8_lossy(s))
                .collect::<Vec<_>>()
                .join(" ")
        }
        RData::CAA(caa) => format!("{} {} {}", caa.issuer_critical(), caa.tag(), 
            caa.value()),
        _ => format!("{:?}", rdata),
    }
}

/// Query result for tracking
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub domain: String,
    pub record_type: RecordType,
    pub resolver: SocketAddr,
    pub response: Option<DnsResponse>,
    pub error: Option<String>,
    pub elapsed_ms: u64,
}

impl QueryResult {
    /// Create a successful result
    pub fn success(
        domain: String,
        record_type: RecordType,
        resolver: SocketAddr,
        response: DnsResponse,
        elapsed_ms: u64,
    ) -> Self {
        Self {
            domain,
            record_type,
            resolver,
            response: Some(response),
            error: None,
            elapsed_ms,
        }
    }

    /// Create an error result
    pub fn error(
        domain: String,
        record_type: RecordType,
        resolver: SocketAddr,
        error: String,
        elapsed_ms: u64,
    ) -> Self {
        Self {
            domain,
            record_type,
            resolver,
            response: None,
            error: Some(error),
            elapsed_ms,
        }
    }

    /// Check if this result represents a successful resolution
    pub fn is_success(&self) -> bool {
        self.response.as_ref().map_or(false, |r| r.is_success())
    }

    /// Get the resolved data if available
    pub fn get_data(&self) -> Option<&str> {
        self.response.as_ref()?.first_answer()
    }
}