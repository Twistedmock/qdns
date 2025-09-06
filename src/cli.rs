use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Ultra-fast DNS resolver for mass domain enumeration
#[derive(Parser, Clone)]
#[command(name = "qdns")]
#[command(about = "Ultra-fast raw UDP DNS resolver for mass domain enumeration")]
#[command(version = "0.1.0")]
pub struct Args {
    /// Input file containing domains to resolve (one per line)
    #[arg(short = 'i', long = "input", help = "Input file with domains to resolve")]
    pub input: Option<PathBuf>,

    /// DNS resolvers to use (can be specified multiple times)
    /// 
    /// Default: Uses a curated set of 31 stable public DNS resolvers including:
    /// - Cloudflare: 1.1.1.1, 1.0.0.1
    /// - Google: 8.8.8.8, 8.8.4.4  
    /// - Quad9: 9.9.9.9, 149.112.112.112
    /// - OpenDNS: 208.67.222.222, 208.67.220.220
    /// - Plus 23 additional high-performance resolvers for redundancy
    /// 
    /// For maximum performance, run a local recursive resolver like:
    /// - Unbound: https://unbound.docs.nlnetlabs.nl/
    /// - Knot Resolver: https://www.knot-resolver.cz/
    /// - systemd-resolved (if available)
    /// 
    /// Note: Public DNS resolvers will rate-limit and drop queries under high load!
    #[arg(
        short = 'r',
        long = "resolver",
        help = "DNS resolver address (IP:port) - defaults to curated stable resolver set"
    )]
    pub resolvers: Vec<SocketAddr>,

    /// Maximum number of concurrent in-flight queries
    /// 
    /// Default: min(50,000, num_cpus * 5,000)
    /// This creates a sliding window of queries to maintain pipeline saturation
    /// without overwhelming the network stack.
    #[arg(
        short = 'c',
        long = "concurrency",
        help = "Maximum concurrent in-flight queries (sliding window)"
    )]
    pub concurrency: Option<usize>,

    /// Number of retry attempts for failed queries
    #[arg(
        long = "retries",
        help = "Number of retry attempts",
        default_value = "2"
    )]
    pub retries: u32,

    /// Query timeout in milliseconds
    #[arg(
        short = 't',
        long = "timeout",
        help = "Query timeout in milliseconds",
        default_value = "1000"
    )]
    pub timeout: u64,

    /// Output file for successful resolutions
    #[arg(short = 'o', long = "output", help = "Output file for results")]
    pub output: Option<PathBuf>,

    /// Number of worker threads
    #[arg(
        long = "threads",
        help = "Number of worker threads",
        default_value_t = num_cpus::get()
    )]
    pub threads: usize,

    /// Query type (A, AAAA, CNAME, etc.)
    #[arg(
        short = 'q',
        long = "qtype",
        help = "DNS query type",
        default_value = "A"
    )]
    pub query_type: String,

    /// Enable verbose output
    #[arg(short = 'v', long = "verbose", help = "Enable verbose output")]
    pub verbose: bool,

    /// Only output successful resolutions (no NXDOMAIN/SERVFAIL)
    #[arg(long = "success-only", help = "Only output successful resolutions")]
    pub success_only: bool,

    /// Rate limit per resolver (queries per second)
    #[arg(
        long = "rate-limit",
        help = "Rate limit per resolver (qps)",
        default_value = "10000"
    )]
    pub rate_limit: u32,

    /// Enable raw mode (direct authoritative queries)
    #[arg(long = "raw", help = "Enable raw mode for direct queries")]
    pub raw_mode: bool,

    /// Domains to resolve (if no input file specified)
    #[arg(help = "Domains to resolve")]
    pub domains: Vec<String>,
}

impl Args {
    /// Check if custom resolvers were provided via CLI
    pub fn has_custom_resolvers(&self) -> bool {
        !self.resolvers.is_empty()
    }

    /// Validate and normalize arguments
    pub fn validate(&mut self) -> anyhow::Result<()> {
        // Ensure we have input domains
        if self.input.is_none() && self.domains.is_empty() {
            return Err(anyhow::anyhow!(
                "Must specify either --input file or provide domains as arguments"
            ));
        }

        // Set smart default for concurrency if not specified
        if self.concurrency.is_none() {
            let cpu_count = num_cpus::get();
            let default_concurrency = std::cmp::min(50_000, cpu_count * 5_000);
            self.concurrency = Some(default_concurrency);
            tracing::info!("Using default concurrency: {} ({}x CPU cores)", default_concurrency, cpu_count);
        }

        let concurrency = self.get_concurrency();

        // Validate concurrency limits
        if concurrency == 0 {
            return Err(anyhow::anyhow!("Concurrency must be greater than 0"));
        }

        if concurrency > 1_000_000 {
            tracing::warn!("Very high concurrency ({}), this may cause system issues", concurrency);
        }

        // Validate timeout
        if self.timeout == 0 {
            return Err(anyhow::anyhow!("Timeout must be greater than 0"));
        }

        // Validate threads
        if self.threads == 0 {
            self.threads = 1;
        }

        // Warn about public DNS resolvers if custom ones are provided
        if !self.resolvers.is_empty() {
            let public_resolvers = [
                "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", 
                "9.9.9.9", "208.67.222.222", "208.67.220.220"
            ];
            
            for resolver in &self.resolvers {
                let ip_str = resolver.ip().to_string();
                if public_resolvers.contains(&ip_str.as_str()) {
                    tracing::warn!(
                        "⚠️  Using public DNS resolver {} - expect rate limiting and dropped queries under high load!", 
                        resolver
                    );
                    tracing::warn!(
                        "💡 For best performance, install and use a local recursive resolver like Unbound (127.0.0.1:53)"
                    );
                    break;
                }
            }
        }

        Ok(())
    }

    /// Get the effective concurrency value
    pub fn get_concurrency(&self) -> usize {
        self.concurrency.unwrap_or_else(|| {
            let cpu_count = num_cpus::get();
            std::cmp::min(50_000, cpu_count * 5_000)
        })
    }

    /// Get the query type as a trust-dns RecordType
    pub fn get_record_type(&self) -> anyhow::Result<trust_dns_proto::rr::RecordType> {
        use trust_dns_proto::rr::RecordType;
        
        match self.query_type.to_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "CNAME" => Ok(RecordType::CNAME),
            "MX" => Ok(RecordType::MX),
            "NS" => Ok(RecordType::NS),
            "PTR" => Ok(RecordType::PTR),
            "SOA" => Ok(RecordType::SOA),
            "SRV" => Ok(RecordType::SRV),
            "TXT" => Ok(RecordType::TXT),
            "CAA" => Ok(RecordType::CAA),
            _ => Err(anyhow::anyhow!("Unsupported query type: {}", self.query_type)),
        }
    }
}

// Re-export num_cpus for convenience
pub use num_cpus;