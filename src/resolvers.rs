use anyhow::{Context, Result};
use std::net::SocketAddr;
use tracing::{info, warn, error};

/// Default stable resolver set for high-performance DNS resolution
/// These are carefully curated for reliability and performance
const DEFAULT_RESOLVERS: &[&str] = &[
    // Cloudflare
    "1.1.1.1:53",
    "1.0.0.1:53",
    
    // Google Public DNS
    "8.8.8.8:53",
    "8.8.4.4:53",
    
    // Quad9
    "9.9.9.9:53",
    "149.112.112.112:53",
    
    // OpenDNS
    "208.67.222.222:53",
    "208.67.220.220:53",
    
    // Additional high-performance resolvers
    "134.195.4.2:53",      // DNS.SB
    "159.89.120.99:53",    // DigitalOcean
    "185.228.168.9:53",    // CleanBrowsing
    "185.228.169.9:53",    // CleanBrowsing Secondary
    "195.46.39.39:53",     // SafeDNS
    "195.46.39.40:53",     // SafeDNS Secondary
    "205.171.2.65:53",     // CenturyLink
    "205.171.3.65:53",     // CenturyLink Secondary
    "216.146.35.35:53",    // Dyn
    "216.146.36.36:53",    // Dyn Secondary
    "64.6.64.6:53",        // Verisign
    "64.6.65.6:53",        // Verisign Secondary
    "74.82.42.42:53",      // Hurricane Electric
    "76.76.10.0:53",       // Control D
    "76.76.2.0:53",        // Control D Secondary
    "77.88.8.1:53",        // Yandex
    "77.88.8.8:53",        // Yandex Secondary
    "8.20.247.20:53",      // Comodo Secure
    "8.26.56.26:53",       // Comodo Secure Secondary
    "84.200.69.80:53",     // DNS.WATCH
    "84.200.70.40:53",     // DNS.WATCH Secondary
    "89.233.43.71:53",     // UncensoredDNS
    "91.239.100.100:53",   // UncensoredDNS Secondary
    
    // UDP-prefixed resolvers for explicit protocol specification
    "udp:1.1.1.1:53",         // Cloudflare
    "udp:1.0.0.1:53",         // Cloudflare
    "udp:8.8.8.8:53",         // Google
    "udp:8.8.4.4:53",         // Google
    "udp:9.9.9.9:53",         // Quad9
    "udp:149.112.112.112:53", // Quad9
    "udp:208.67.222.222:53",  // Open DNS
    "udp:208.67.220.220:53",  // Open DNS
];

/// Get default stable resolvers with fallback parsing
fn get_stable_resolvers() -> Vec<SocketAddr> {
    let mut resolvers = Vec::new();
    
    for resolver_str in DEFAULT_RESOLVERS {
        // Handle UDP prefix if present
        let addr_str = if resolver_str.starts_with("udp:") {
            &resolver_str[4..] // Strip "udp:" prefix
        } else {
            resolver_str
        };
        
        match addr_str.parse::<SocketAddr>() {
            Ok(addr) => resolvers.push(addr),
            Err(e) => {
                warn!("Failed to parse default resolver {}: {}", resolver_str, e);
            }
        }
    }
    
    if resolvers.is_empty() {
        // Ultimate fallback - should never happen with hardcoded addresses
        warn!("⚠️ All default resolvers failed to parse, falling back to localhost");
        resolvers.push("127.0.0.1:53".parse().unwrap());
    }
    
    info!("✅ Using {} stable default resolvers", resolvers.len());
    resolvers
}

/// Parse resolvers from text content (for custom resolver files)
fn parse_resolvers(content: &str) -> Result<Vec<SocketAddr>> {
    let mut resolvers = Vec::new();
    let mut line_count = 0;
    let mut valid_count = 0;
    
    for line in content.lines() {
        line_count += 1;
        let line = line.trim();
        
        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        // Handle UDP prefix if present
        let addr_str = if line.starts_with("udp:") {
            &line[4..] // Strip "udp:" prefix
        } else {
            line
        };
        
        // Parse IP address, add default port 53 if not specified
        let resolver_addr = if addr_str.contains(':') {
            addr_str.parse::<SocketAddr>()
        } else {
            // Add default DNS port 53
            format!("{}:53", addr_str).parse::<SocketAddr>()
        };
        
        match resolver_addr {
            Ok(addr) => {
                resolvers.push(addr);
                valid_count += 1;
            }
            Err(e) => {
                warn!("Failed to parse resolver on line {}: '{}' - {}", line_count, line, e);
            }
        }
    }
    
    if resolvers.is_empty() {
        return Err(anyhow::anyhow!(
            "No valid resolvers found in content"
        ));
    }
    
    info!(
        "📊 Parsed {} valid resolvers from {} lines", 
        valid_count, line_count
    );
    
    Ok(resolvers)
}

/// Get default resolvers (stable set, no external downloads)
pub fn get_default_resolvers() -> Vec<SocketAddr> {
    get_stable_resolvers()
}

/// Parse resolvers from a custom file (for --resolvers-file option)
pub fn parse_resolvers_from_file(content: &str) -> Result<Vec<SocketAddr>> {
    parse_resolvers(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_resolvers() {
        let content = r#"
# Test resolvers
1.1.1.1
8.8.8.8:53
192.168.1.1:5353
udp:9.9.9.9:53
udp:1.0.0.1

# Invalid entries
invalid-ip
256.256.256.256
"#;
        
        let resolvers = parse_resolvers(content).unwrap();
        assert_eq!(resolvers.len(), 5);
        assert_eq!(resolvers[0], "1.1.1.1:53".parse().unwrap());
        assert_eq!(resolvers[1], "8.8.8.8:53".parse().unwrap());
        assert_eq!(resolvers[2], "192.168.1.1:5353".parse().unwrap());
        assert_eq!(resolvers[3], "9.9.9.9:53".parse().unwrap()); // UDP prefix stripped
        assert_eq!(resolvers[4], "1.0.0.1:53".parse().unwrap()); // UDP prefix stripped, port added
    }
    
    #[test]
    fn test_parse_empty_content() {
        let content = "# Only comments\n\n";
        let result = parse_resolvers(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_resolvers() {
        let resolvers = get_default_resolvers();
        assert!(!resolvers.is_empty());
        assert_eq!(resolvers.len(), 39); // Should have all 39 default resolvers (31 + 8 UDP-prefixed)
        
        // Verify some key resolvers are present
        assert!(resolvers.contains(&"1.1.1.1:53".parse().unwrap()));
        assert!(resolvers.contains(&"8.8.8.8:53".parse().unwrap()));
        assert!(resolvers.contains(&"9.9.9.9:53".parse().unwrap()));
    }
}