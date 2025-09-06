use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, warn, error};

const RESOLVERS_URL: &str = "https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers-trusted.txt";
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Download and parse resolvers from the Trickest resolvers list
pub async fn download_resolvers() -> Result<Vec<SocketAddr>> {
    info!("📡 Downloading trusted resolvers from {}", RESOLVERS_URL);
    
    let client = reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .user_agent("qdns/0.1.0")
        .build()
        .context("Failed to create HTTP client")?;
    
    let response = client
        .get(RESOLVERS_URL)
        .send()
        .await
        .context("Failed to download resolvers list")?;
    
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
    
    info!("✅ Downloaded {} resolvers from Trickest trusted list", resolvers.len());
    
    Ok(resolvers)
}

/// Parse resolvers from text content
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
            "No valid resolvers found in downloaded content"
        ));
    }
    
    info!(
        "📊 Parsed {} valid resolvers from {} lines", 
        valid_count, line_count
    );
    
    Ok(resolvers)
}

/// Download resolvers with fallback to default
pub async fn get_default_resolvers() -> Vec<SocketAddr> {
    match download_resolvers().await {
        Ok(resolvers) => resolvers,
        Err(e) => {
            error!("Failed to download resolvers: {}", e);
            warn!("⚠️  Falling back to local resolver 127.0.0.1:53");
            vec!["127.0.0.1:53".parse().unwrap()]
        }
    }
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
}