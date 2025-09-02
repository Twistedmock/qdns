use anyhow::{Context, Result};
use clap::Parser;
use crossbeam_channel::{Receiver, Sender};
use dashmap::DashMap;
use futures::future::join_all;
use once_cell::sync::Lazy;
use std::{
    collections::HashSet,
    fs::File,
    io::{self, BufRead, BufReader, Write},
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{sync::Semaphore, time::sleep};
use trust_dns_proto::rr::RecordType;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol},
    error::ResolveError,
    AsyncResolver, TokioAsyncResolver,
};

// System optimization function based on the high-performance script
fn configure_system_for_performance(verbose: bool) -> io::Result<()> {
    unsafe {
        let target_limit = 1_048_576;
        let rlimit = libc::rlimit {
            rlim_cur: target_limit,
            rlim_max: target_limit,
        };
        if libc::setrlimit(libc::RLIMIT_NOFILE, &rlimit) != 0 {
            let err = io::Error::last_os_error();
            if verbose {
                eprintln!(
                    "⚠️  Failed to set file descriptor limit to {}. Run 'ulimit -n {}' manually: {}",
                    target_limit, target_limit, err
                );
            }
        } else if verbose {
            eprintln!("🔧 Set file descriptor limit to {}", target_limit);
        }
    }

    #[cfg(target_os = "linux")]
    {
        let sysctl_settings = [
            ("net.ipv4.ip_local_port_range", "10000 65535"),
            ("net.ipv4.tcp_fin_timeout", "15"),
            ("net.ipv4.tcp_tw_reuse", "1"),
            ("net.core.somaxconn", "65535"),
            ("net.core.netdev_max_backlog", "5000"),
            ("net.ipv4.tcp_max_syn_backlog", "8192"),
            ("fs.file-max", "2097152"),
        ];
        
        for (key, value) in sysctl_settings.iter() {
            let cmd = std::process::Command::new("sysctl")
                .arg("-w")
                .arg(format!("{}={}", key, value))
                .output();
            match cmd {
                Ok(output) if output.status.success() => {
                    if verbose {
                        eprintln!("🔧 Set {} = {}", key, value);
                    }
                }
                Ok(output) => {
                    let err = String::from_utf8_lossy(&output.stderr);
                    if verbose {
                        eprintln!(
                            "⚠️  Failed to set {} = {}. Run 'sudo sysctl -w {}={}' manually: {}",
                            key, value, key, value, err
                        );
                    }
                }
                Err(e) => {
                    if verbose {
                        eprintln!(
                            "⚠️  Failed to run sysctl for {} = {}: {}",
                            key, value, e
                        );
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if verbose {
            eprintln!("🍎 macOS detected. For optimal performance, run:");
            eprintln!("  sudo sysctl -w kern.maxfiles=2097152");
            eprintln!("  sudo sysctl -w kern.maxfilesperproc=1048576");
            eprintln!("  sudo sysctl -w net.inet.ip.portrange.first=10000");
        }
    }

    Ok(())
}

// Calculate optimal thread count based on system resources
fn calculate_optimal_threads() -> usize {
    let cpu_count = num_cpus::get();
    // For DNS resolution, we can go much higher than CPU count due to I/O bound nature
    // Aim for maximum performance while being reasonable
    let base_threads = cpu_count * 5000; // Very aggressive for DNS I/O
    
    // Cap at system limits but allow very high concurrency
    base_threads.min(500_000).max(10_000)
}

#[derive(Parser)]
#[command(name = "qdns")]
#[command(about = "Ultra-fast DNS resolver with subdomain bruteforcing")]
struct Cli {
    // INPUT
    #[arg(short = 'l', long = "list", help = "List of sub(domains)/hosts to resolve")]
    list: Option<String>,
    
    #[arg(short = 'd', long = "domain", help = "List of domain to bruteforce")]
    domain: Option<String>,
    
    #[arg(short = 'w', long = "wordlist", help = "List of words to bruteforce")]
    wordlist: Option<String>,
    
    #[arg(short = 'r', long = "resolver", help = "List of resolvers to use")]
    resolver: Option<String>,

    // QUERY TYPES
    #[arg(short = 'a', help = "Query A record")]
    a: bool,
    
    #[arg(long = "aaaa", help = "Query AAAA record")]
    aaaa: bool,
    
    #[arg(long = "cname", help = "Query CNAME record")]
    cname: bool,
    
    #[arg(long = "ns", help = "Query NS record")]
    ns: bool,
    
    #[arg(long = "txt", help = "Query TXT record")]
    txt: bool,
    
    #[arg(long = "srv", help = "Query SRV record")]
    srv: bool,
    
    #[arg(long = "ptr", help = "Query PTR record")]
    ptr: bool,
    
    #[arg(long = "mx", help = "Query MX record")]
    mx: bool,
    
    #[arg(long = "soa", help = "Query SOA record")]
    soa: bool,
    
    #[arg(long = "any", help = "Query ANY record")]
    any: bool,
    
    #[arg(long = "axfr", help = "Query AXFR")]
    axfr: bool,
    
    #[arg(long = "caa", help = "Query CAA record")]
    caa: bool,
    
    #[arg(long = "all", help = "Query all DNS records")]
    all: bool,
    
    #[arg(long = "recon", help = "Query all DNS records (alias for --all)")]
    recon: bool,
    
    #[arg(short = 'e', long = "exclude-type", help = "DNS query type to exclude")]
    exclude_type: Vec<String>,

    // FILTER
    #[arg(long = "re", help = "Display DNS response")]
    resp: bool,
    
    #[arg(long = "ro", help = "Display DNS response only")]
    resp_only: bool,
    
    #[arg(long = "rc", help = "Filter result by DNS status code")]
    rcode: Option<String>,

    // RATE-LIMIT
    #[arg(short = 't', long = "threads", default_value_t = calculate_optimal_threads(), help = "Number of concurrent threads")]
    threads: usize,

    // OUTPUT
    #[arg(short = 'o', long = "output", help = "File to write output")]
    output: Option<String>,

    // DEBUG
    #[arg(long = "silent", help = "Display only results")]
    silent: bool,
    
    #[arg(short = 'v', long = "verbose", help = "Display verbose output")]
    verbose: bool,
    
    #[arg(long = "raw", help = "Display raw DNS response")]
    raw: bool,
    
    #[arg(long = "debug", help = "Display debug output")]
    debug: bool,
    
    #[arg(long = "retry", default_value = "3", help = "Number of DNS attempts [default: 3]")]
    retry: u32,

    #[arg(long = "all-results", help = "Output all DNS responses, including NXDOMAIN/SERVFAIL")]
    all_results: bool,
}

#[derive(Debug, Clone)]
struct DnsResult {
    domain: String,
    record_type: RecordType,
    data: String,
    rcode: String,
    response_time: Duration,
}

#[derive(Debug, Clone)]
struct QueryConfig {
    record_types: Vec<RecordType>,
    retry_count: u32,
}

static PROGRESS_COUNTER: AtomicU64 = AtomicU64::new(0);
static TOTAL_COUNTER: AtomicU64 = AtomicU64::new(0);

static RESOLVER_CACHE: Lazy<DashMap<String, Arc<TokioAsyncResolver>>> = Lazy::new(DashMap::new);

async fn create_resolver(nameserver: Option<&str>) -> Result<Arc<TokioAsyncResolver>> {
    let key = nameserver.unwrap_or("default").to_string();
    
    if let Some(resolver) = RESOLVER_CACHE.get(&key) {
        return Ok(resolver.clone());
    }

    let mut config = ResolverConfig::default();
    let mut opts = ResolverOpts::default();
    
    // Ultra-aggressive performance settings for maximum speed
    opts.timeout = Duration::from_millis(100); // Very short timeout for speed
    opts.attempts = 1; // Single attempt for speed
    opts.ndots = 0; // Don't append search domains
    opts.edns0 = true; // Enable EDNS for better performance
    opts.validate = false; // Skip DNSSEC validation for speed
    opts.ip_strategy = trust_dns_resolver::config::LookupIpStrategy::Ipv4thenIpv6; // Prefer IPv4 for speed
    opts.cache_size = 1024; // Small cache to avoid memory overhead
    opts.use_hosts_file = false; // Skip hosts file for speed
    opts.positive_min_ttl = Some(Duration::from_secs(1)); // Minimum cache time
    opts.negative_min_ttl = Some(Duration::from_millis(100)); // Very short negative cache
    opts.positive_max_ttl = Some(Duration::from_secs(30)); // Short positive cache for accuracy
    opts.num_concurrent_reqs = 1000; // High concurrency per resolver

    if let Some(ns) = nameserver {
        if let Ok(ip) = ns.parse::<IpAddr>() {
            let socket_addr = SocketAddr::new(ip, 53);
            config = ResolverConfig::from_parts(
                None, 
                vec![], 
                vec![NameServerConfig::new(socket_addr, Protocol::Udp)]
            );
        }
    }

    let resolver = Arc::new(AsyncResolver::tokio(config, opts));
    RESOLVER_CACHE.insert(key, resolver.clone());
    Ok(resolver)
}

async fn resolve_domain(
    domain: &str,
    record_type: RecordType,
    resolver: Arc<TokioAsyncResolver>,
    retry_count: u32,
) -> Result<Vec<DnsResult>, ResolveError> {
    let start = Instant::now();
    let mut last_error = None;

    for attempt in 0..=retry_count {
        let result = match record_type {
            RecordType::A | RecordType::AAAA => {
                resolver.lookup_ip(domain).await.map(|lookup| {
                    lookup.iter()
                        .filter_map(|ip| match (ip, record_type) {
                            (IpAddr::V4(v4), RecordType::A) => Some(DnsResult {
                                domain: domain.to_string(),
                                record_type,
                                data: v4.to_string(),
                                rcode: "NOERROR".to_string(),
                                response_time: start.elapsed(),
                            }),
                            (IpAddr::V6(v6), RecordType::AAAA) => Some(DnsResult {
                                domain: domain.to_string(),
                                record_type,
                                data: v6.to_string(),
                                rcode: "NOERROR".to_string(),
                                response_time: start.elapsed(),
                            }),
                            _ => None,
                        })
                        .collect()
                })
            },
            _ => {
                resolver.lookup(domain, record_type).await.map(|lookup| {
                    lookup.iter()
                        .map(|record| {
                            let data_str = format!("{}", record);
                            
                            DnsResult {
                                domain: domain.to_string(),
                                record_type,
                                data: data_str,
                                rcode: "NOERROR".to_string(),
                                response_time: start.elapsed(),
                            }
                        })
                        .collect()
                })
            }
        };

        match result {
            Ok(results) => return Ok(results),
            Err(e) => {
                last_error = Some(e);
                if attempt < retry_count {
                    sleep(Duration::from_millis(100 * (attempt as u64 + 1))).await;
                }
            }
        }
    }

    Err(last_error.unwrap())
}

fn read_input_file(path: &str) -> Result<Vec<String>> {
    if path == "-" {
        let stdin = std::io::stdin();
        return Ok(stdin.lock().lines().collect::<Result<Vec<_>, _>>()?);
    }

    let file = File::open(path).context(format!("Failed to open file: {}", path))?;
    let reader = BufReader::new(file);
    Ok(reader.lines().collect::<Result<Vec<_>, _>>()?)
}

fn parse_comma_separated_or_file(input: &str) -> Result<Vec<String>> {
    if Path::new(input).exists() {
        read_input_file(input)
    } else {
        Ok(input.split(',').map(|s| s.trim().to_string()).collect())
    }
}

fn determine_record_types(args: &Cli) -> Vec<RecordType> {
    let mut types = Vec::new();
    
    if args.all || args.recon {
        return vec![
            RecordType::A, RecordType::AAAA, RecordType::CNAME, 
            RecordType::NS, RecordType::TXT, RecordType::SRV,
            RecordType::PTR, RecordType::MX, RecordType::SOA, 
            RecordType::CAA
        ];
    }
    
    if args.a { types.push(RecordType::A); }
    if args.aaaa { types.push(RecordType::AAAA); }
    if args.cname { types.push(RecordType::CNAME); }
    if args.ns { types.push(RecordType::NS); }
    if args.txt { types.push(RecordType::TXT); }
    if args.srv { types.push(RecordType::SRV); }
    if args.ptr { types.push(RecordType::PTR); }
    if args.mx { types.push(RecordType::MX); }
    if args.soa { types.push(RecordType::SOA); }
    if args.any { types.push(RecordType::ANY); }
    if args.caa { types.push(RecordType::CAA); }
    
    if types.is_empty() {
        types.push(RecordType::A);
    }
    
    // Filter out excluded types
    let excluded: HashSet<_> = args.exclude_type.iter()
        .map(|s| match s.to_lowercase().as_str() {
            "a" => RecordType::A,
            "aaaa" => RecordType::AAAA,
            "cname" => RecordType::CNAME,
            "ns" => RecordType::NS,
            "txt" => RecordType::TXT,
            "srv" => RecordType::SRV,
            "ptr" => RecordType::PTR,
            "mx" => RecordType::MX,
            "soa" => RecordType::SOA,
            "caa" => RecordType::CAA,
            _ => RecordType::A, // default fallback
        })
        .collect();
        
    types.retain(|t| !excluded.contains(t));
    types
}

async fn process_domains(
    domains: Vec<String>,
    query_config: QueryConfig,
    resolver: Arc<TokioAsyncResolver>,
    sender: Sender<DnsResult>,
    semaphore: Arc<Semaphore>,
    silent: bool,
    resp_only: bool,
) {
    let tasks = domains.into_iter().flat_map(|domain| {
        let resolver_clone = resolver.clone();
        let sender_clone = sender.clone();
        let semaphore_clone = semaphore.clone();
        
        query_config.record_types.iter().map(move |&record_type| {
            let domain = domain.clone();
            let resolver = resolver_clone.clone();
            let sender = sender_clone.clone();
            let semaphore = semaphore_clone.clone();
            let retry_count = query_config.retry_count;
            
            async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                match resolve_domain(&domain, record_type, resolver, retry_count).await {
                    Ok(results) => {
                        for result in results {
                            let _ = sender.send(result);
                        }
                    }
                    Err(e) => {
                        let error_result = DnsResult {
                            domain: domain.clone(),
                            record_type,
                            data: format!("Error: {}", e),
                            rcode: if format!("{}", e).contains("no record") || format!("{}", e).contains("NXDOMAIN") {
                                "NXDOMAIN".to_string()
                            } else {
                                "SERVFAIL".to_string()
                            },
                            response_time: Duration::from_millis(0),
                        };
                        let _ = sender.send(error_result);
                    }
                }
                
                let count = PROGRESS_COUNTER.fetch_add(1, Ordering::Relaxed);
                if count % 10000 == 0 && !silent && !resp_only {
                    let total = TOTAL_COUNTER.load(Ordering::Relaxed);
                    eprintln!("Progress: {}/{} ({:.1}%)", count, total, (count as f64 / total as f64) * 100.0);
                }
            }
        })
    });

    join_all(tasks).await;
}

fn should_display_result(result: &DnsResult, rcode_filter: &Option<String>, args: &Cli) -> bool {
    if let Some(filter) = rcode_filter {
        let allowed_codes: HashSet<_> = filter
            .split(',')
            .map(|s| s.trim().to_uppercase())
            .collect();
        return allowed_codes.contains(&result.rcode.to_uppercase());
    }
    true
}

fn format_output(result: &DnsResult, args: &Cli) -> String {
    // For resp_only, only return successful results without errors
    if args.resp_only {
        if result.rcode == "NOERROR" && !result.data.starts_with("Error:") {
            return result.data.clone();
        } else {
            return String::new(); // Return empty string for errors
        }
    }
    
    if args.resp {
        return format!("{} {} {}", result.domain, result.record_type, result.data);
    }
    
    if args.raw || args.debug {
        return format!(
            "{} {} {} {} {}ms",
            result.domain,
            result.record_type,
            result.data,
            result.rcode,
            result.response_time.as_millis()
        );
    }
    
    if result.rcode == "NOERROR" && !result.data.starts_with("Error:") {
        format!("{}", result.domain)
    } else if args.verbose {
        format!("{} [{}]", result.domain, result.rcode)
    } else {
        String::new() // Don't show failed resolutions by default
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let start_time = Instant::now();
    
    if !args.silent && !args.resp_only {
        eprintln!("🚀 QDNS - Ultra-fast DNS resolver starting...");
        eprintln!("⚡ Configuring system for maximum performance...");
    }

    // Configure system for high performance
    configure_system_for_performance(!args.silent && !args.resp_only).unwrap_or_else(|e| {
        if !args.silent && !args.resp_only {
            eprintln!("⚠️  System configuration warning: {}", e);
        }
    });

    // Determine record types to query
    let record_types = determine_record_types(&args);
    
    // Setup resolver
    let resolver_list = if let Some(ref resolver_input) = args.resolver {
        parse_comma_separated_or_file(resolver_input)?
    } else {
        // Use high-performance trusted DNS resolvers for maximum speed and reliability
        vec![
            "1.1.1.1".to_string(),      // Cloudflare Primary
            "1.0.0.1".to_string(),      // Cloudflare Secondary  
            "8.8.8.8".to_string(),      // Google Primary
            "8.8.4.4".to_string(),      // Google Secondary
            "9.9.9.9".to_string(),      // Quad9
            "208.67.222.222".to_string(), // OpenDNS
            "208.67.220.220".to_string(), // OpenDNS
            "149.112.112.112".to_string(), // Quad9 Secondary
            "76.76.2.0".to_string(),    // Control D
            "76.76.10.0".to_string(),   // Control D
            "185.228.168.9".to_string(), // CleanBrowsing
            "185.228.169.9".to_string(), // CleanBrowsing
        ]
    };
    
    let resolver = create_resolver(resolver_list.first().map(|s| s.as_str())).await?;

    // Collect all domains to process
    let mut all_domains = Vec::new();
    
    // Add domains from list
    if let Some(ref list_file) = args.list {
        all_domains.extend(read_input_file(list_file)?);
    }
    
    // Generate domains from bruteforcing
    if let Some(ref domain_input) = args.domain {
        let domains = parse_comma_separated_or_file(domain_input)?;
        
        if let Some(ref wordlist_input) = args.wordlist {
            let wordlist = parse_comma_separated_or_file(wordlist_input)?;
            
            for domain in &domains {
                for word in &wordlist {
                    all_domains.push(format!("{}.{}", word, domain));
                }
            }
        } else {
            all_domains.extend(domains);
        }
    }
    
    if all_domains.is_empty() {
        return Err(anyhow::anyhow!("No domains to resolve. Use -l, -d, or provide input via stdin"));
    }

    // Remove duplicates
    all_domains.sort();
    all_domains.dedup();
    
    let total_queries = all_domains.len() * record_types.len();
    TOTAL_COUNTER.store(total_queries as u64, Ordering::Relaxed);
    
    if !args.silent && !args.resp_only {
        eprintln!("📊 Processing {} domains with {} record types ({} total queries)", 
                 all_domains.len(), record_types.len(), total_queries);
    }

    // Setup concurrency control
    // Auto-scale threads if input is less than default
    let thread_count = if all_domains.len() < args.threads {
        all_domains.len().max(1)
    } else {
        args.threads
    };

    let semaphore = Arc::new(Semaphore::new(thread_count));
    if !args.silent && !args.resp_only {
        eprintln!("🔧 Using {} concurrent threads", thread_count);
    }
    let (sender, receiver): (Sender<DnsResult>, Receiver<DnsResult>) = crossbeam_channel::unbounded();
    
    let query_config = QueryConfig {
        record_types,
        retry_count: args.retry,
    };

    // Start processing
    let process_handle = tokio::spawn(process_domains(
        all_domains,
        query_config,
        resolver,
        sender,
        semaphore,
        args.silent,
        args.resp_only,
    ));

    // Setup output
    let mut output_writer: Box<dyn Write> = if let Some(ref output_file) = args.output {
        Box::new(File::create(output_file)?)
    } else {
        Box::new(std::io::stdout())
    };

    // Process results
    let mut results_count = 0;
    let mut successful_count = 0;
    
    while let Ok(result) = receiver.recv() {
        results_count += 1;
        
        if should_display_result(&result, &args.rcode, &args) {
            let formatted = format_output(&result, &args);
            if !formatted.is_empty() {
                writeln!(output_writer, "{}", formatted)?;
                if result.rcode == "NOERROR" && !result.data.starts_with("Error:") {
                    successful_count += 1;
                }
            }
        }
        
        // Check if we've processed all results
        if results_count >= total_queries {
            break;
        }
    }

    process_handle.await?;
    
    let elapsed = start_time.elapsed();
    
    if !args.silent && !args.resp_only {
        eprintln!("✅ Completed in {:.2}s", elapsed.as_secs_f64());
        eprintln!("📈 Processed {} queries ({:.0} queries/sec)", 
                 results_count, results_count as f64 / elapsed.as_secs_f64());
        eprintln!("🎯 Successful resolutions: {}", successful_count);
    }

    Ok(())
}
