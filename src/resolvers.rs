use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, warn, error};

const TRICKEST_RESOLVERS_URL: &str = "https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt";
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Parse resolvers from text content (for custom resolver files and Trickest list)
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

/// Get default resolvers (curated set + downloaded Trickest list)
pub async fn get_default_resolvers() -> Vec<SocketAddr> {
    let mut all_resolvers = get_stable_resolvers();
    
    // Download and append Trickest resolvers
    match download_trickest_resolvers().await {
        Ok(mut trickest_resolvers) => {
            let original_count = all_resolvers.len();
            
            // Remove duplicates by converting to set-like behavior
            trickest_resolvers.retain(|resolver| !all_resolvers.contains(resolver));
            
            let new_count = trickest_resolvers.len();
            all_resolvers.extend(trickest_resolvers);
            
            info!(
                "✅ Combined resolver pool: {} curated + {} from Trickest = {} total",
                original_count, new_count, all_resolvers.len()
            );
        }
        Err(e) => {
            warn!("⚠️ Failed to download Trickest resolvers: {}", e);
            warn!("🔄 Continuing with {} curated resolvers only", all_resolvers.len());
        }
    }
    
    all_resolvers
}

/// Download and parse resolvers from the Trickest resolvers list
async fn download_trickest_resolvers() -> Result<Vec<SocketAddr>> {
    info!("📡 Downloading resolvers from Trickest list...");
    
    let client = reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .user_agent("qdns/0.1.0")
        .build()
        .context("Failed to create HTTP client")?;
    
    let response = client
        .get(TRICKEST_RESOLVERS_URL)
        .send()
        .await
        .context("Failed to download Trickest resolvers list")?;
    
    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "HTTP error downloading resolvers: {}", 
            response.status()
        ));
    }
    
    let content = response
        .text()
        .await
        .context("Failed to read response body")?;
    
    let resolvers = parse_resolvers(&content)?;
    
    info!("✅ Downloaded {} resolvers from Trickest", resolvers.len());
    
    Ok(resolvers)
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
        // Note: This test only validates the curated resolvers since we can't
        // easily test async network calls in unit tests
        let resolvers = get_stable_resolvers();
        assert!(!resolvers.is_empty());
        assert_eq!(resolvers.len(), 31); // Should have all 31 curated resolvers
        
        // Verify some key resolvers are present
        assert!(resolvers.contains(&"1.1.1.1:53".parse().unwrap()));
        assert!(resolvers.contains(&"8.8.8.8:53".parse().unwrap()));
        assert!(resolvers.contains(&"9.9.9.9:53".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_trickest_download() {
        // This test requires network access and may be flaky in CI
        // Consider making this an integration test
        match download_trickest_resolvers().await {
            Ok(resolvers) => {
                assert!(!resolvers.is_empty());
                println!("Downloaded {} Trickest resolvers", resolvers.len());
            }
            Err(e) => {
                println!("Failed to download Trickest resolvers (expected in offline environments): {}", e);
            }
        }
    }
}