use anyhow::{Context, Result};
use std::net::SocketAddr;
use tracing::{info, warn, error};

/// Default stable resolver set for high-performance DNS resolution
/// These are carefully curated for reliability and performance
const DEFAULT_RESOLVERS: &[&str] = &[
    "1.1.1.1:53",          // Cloudflare Primary
    "1.0.0.1:53",          // Cloudflare Secondary
    "8.8.8.8:53",          // Google Primary
    "8.8.4.4:53",          // Google Secondary
    "9.9.9.9:53",          // Quad9 Primary
    "149.112.112.112:53",  // Quad9 Secondary
    "208.67.222.222:53",   // OpenDNS Primary
    "208.67.220.220:53",   // OpenDNS Secondary
];

/// Get default stable resolvers with fallback parsing
fn get_stable_resolvers() -> Vec<SocketAddr> {
    let mut resolvers = Vec::new();
    
    for resolver_str in DEFAULT_RESOLVERS {
        match resolver_str.parse::<SocketAddr>() {
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
        
        // Parse IP address, add default port 53 if not specified
        let resolver_addr = if line.contains(':') {
            line.parse::<SocketAddr>()
        } else {
            // Add default DNS port 53
            format!("{}:53", line).parse::<SocketAddr>()
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

# Invalid entries
invalid-ip
256.256.256.256
"#;
        
        let resolvers = parse_resolvers(content).unwrap();
        assert_eq!(resolvers.len(), 3);
        assert_eq!(resolvers[0], "1.1.1.1:53".parse().unwrap());
        assert_eq!(resolvers[1], "8.8.8.8:53".parse().unwrap());
        assert_eq!(resolvers[2], "192.168.1.1:5353".parse().unwrap());
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
        assert_eq!(resolvers.len(), 8); // Should have all 8 default resolvers
        
        // Verify some key resolvers are present
        assert!(resolvers.contains(&"1.1.1.1:53".parse().unwrap()));
        assert!(resolvers.contains(&"8.8.8.8:53".parse().unwrap()));
        assert!(resolvers.contains(&"9.9.9.9:53".parse().unwrap()));
    }
}