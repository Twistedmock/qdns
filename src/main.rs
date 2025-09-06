mod cli;
mod packet;
mod engine;
mod system;
mod pool;
mod sharding;
mod resolvers;

use anyhow::Result;
use cli::Args;
use clap::Parser;
use engine::DnsEngine;
use system::SystemOptimizer;
use resolvers::get_default_resolvers;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    time::Instant,
};
use tokio::io::{AsyncWriteExt, BufWriter};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let mut args = Args::parse();
    args.validate()?;

    // Download default resolvers if none were provided
    if !args.has_custom_resolvers() {
        info!("🔍 No custom resolvers provided, downloading default resolvers...");
        args.resolvers = get_default_resolvers().await;
    }

    // Initialize system optimizer
    let optimizer = SystemOptimizer::new(args.verbose);
    
    // Configure system resources for high-performance UDP
    if let Err(e) = optimizer.configure_system() {
        if args.verbose {
            tracing::warn!("System optimization failed: {}", e);
            tracing::warn!("Continuing with default settings...");
        }
    }

    // Calculate optimal concurrency based on system limits
    let original_concurrency = args.get_concurrency();
    let optimized_concurrency = optimizer.calculate_optimal_concurrency(original_concurrency);
    
    if optimized_concurrency != original_concurrency && args.verbose {
        info!(
            "Adjusted concurrency from {} to {} based on system limits", 
            original_concurrency, optimized_concurrency
        );
    }

    let start_time = Instant::now();
    
    info!("🚀 QDNS - Ultra-fast raw UDP DNS resolver starting...");
    info!("⚡ Configuration: {} resolvers, {} concurrency, {} threads", 
          args.resolvers.len(), args.get_concurrency(), args.threads);

    // Get record type
    let record_type = args.get_record_type()?;
    
    // Load domains to resolve
    let domains = load_domains(&args).await?;
    
    if domains.is_empty() {
        return Err(anyhow::anyhow!("No domains to resolve"));
    }

    info!("📊 Loaded {} domains to resolve", domains.len());

    // Create and start the DNS engine
    let engine = match DnsEngine::new(args.clone(), record_type).await {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!("Failed to initialize DNS engine: {}", e);
            std::process::exit(1);
        }
    };
    let mut result_receiver = engine.run(domains.clone()).await?;

    // Setup output writer
    let output_file = setup_output_writer(&args).await?;
    let mut output_writer = BufWriter::new(output_file);

    // Process results
    let mut total_results = 0;
    let mut successful_results = 0;
    
    while let Some(result) = result_receiver.recv().await {
        total_results += 1;
        
        // Handle the result based on configuration
        if result.is_success() {
            successful_results += 1;
            
            if let Some(data) = result.get_data() {
                let output_line = if args.verbose {
                    format!("{} {} {} {}ms\n", result.domain, result.record_type, data, result.elapsed_ms)
                } else {
                    format!("{}\n", result.domain)
                };
                
                output_writer.write_all(output_line.as_bytes()).await?;
            }
        } else if args.verbose {
            // Log failed resolutions to stderr for debugging (not to output file)
            let error_msg = result.error.as_deref().unwrap_or("Unknown error");
            tracing::debug!("Failed: {} - {} ({}ms)", result.domain, error_msg, result.elapsed_ms);
        }
        // Note: Failed resolutions are NOT written to output file
        // They are only logged to stderr in verbose mode for debugging

        // Flush output periodically
        if total_results % 1000 == 0 {
            output_writer.flush().await?;
            
            if args.verbose {
                let progress = (total_results as f64 / domains.len() as f64) * 100.0;
                info!("Progress: {}/{} ({:.1}%) - {} successful", 
                      total_results, domains.len(), progress, successful_results);
            }
        }

        // Break if we've processed all expected results
        if total_results >= domains.len() {
            break;
        }
    }

    // Final flush
    output_writer.flush().await?;

    // Print final statistics
    let elapsed = start_time.elapsed();
    let stats = engine.get_stats();
    
    info!("✅ Completed in {:.2}s", elapsed.as_secs_f64());
    info!("📈 Total results: {} ({:.0} queries/sec)", 
          total_results, total_results as f64 / elapsed.as_secs_f64());
    info!("🎯 Successful resolutions: {} ({:.1}%)", 
          successful_results, (successful_results as f64 / total_results as f64) * 100.0);
    info!("📊 Engine stats: sent={}, received={}, timeouts={}, retries={}, malformed={}", 
          stats.queries_sent.load(std::sync::atomic::Ordering::Relaxed),
          stats.responses_received.load(std::sync::atomic::Ordering::Relaxed),
          stats.timeouts.load(std::sync::atomic::Ordering::Relaxed),
          stats.retries.load(std::sync::atomic::Ordering::Relaxed),
          stats.malformed_domains.load(std::sync::atomic::Ordering::Relaxed));

    // Print resolver health summary if verbose
    if args.verbose {
        let health_summary = engine.get_resolver_health_summary();
        let healthy_count = health_summary.iter().filter(|(_, h)| h.is_healthy).count();
        
        info!("🏥 Resolver Health Summary: {}/{} healthy", healthy_count, health_summary.len());
        
        // Show top 5 and bottom 5 resolvers
        for (i, (resolver, health)) in health_summary.iter().take(5).enumerate() {
            info!("  #{}: {} - Score: {:.2} (Success: {}, Timeouts: {}, Avg: {}ms)", 
                  i + 1, resolver, health.health_score, health.success_count, 
                  health.timeout_count, health.avg_response_time.as_millis());
        }
        
        if health_summary.len() > 10 {
            info!("  ... {} more resolvers in middle ...", health_summary.len() - 10);
        }
        
        // Show worst 5 resolvers
        let worst_start = health_summary.len().saturating_sub(5);
        if worst_start > 5 {
            for (resolver, health) in health_summary.iter().skip(worst_start) {
                info!("  Worst: {} - Score: {:.2} (Success: {}, Timeouts: {}, Avg: {}ms)", 
                      resolver, health.health_score, health.success_count, 
                      health.timeout_count, health.avg_response_time.as_millis());
            }
        }
    }

    Ok(())
}

/// Load domains from input file or command line arguments
async fn load_domains(args: &Args) -> Result<Vec<String>> {
    let mut domains = Vec::new();

    // Load from input file if specified
    if let Some(input_path) = &args.input {
        let file = File::open(input_path)?;
        let reader = BufReader::new(file);
        
        for line in reader.lines() {
            let line = line?;
            let domain = line.trim();
            if !domain.is_empty() && !domain.starts_with('#') {
                domains.push(domain.to_string());
            }
        }
    }

    // Add domains from command line arguments
    domains.extend(args.domains.clone());

    // Remove duplicates and sort
    domains.sort();
    domains.dedup();

    Ok(domains)
}

/// Setup output writer (file or stdout)
async fn setup_output_writer(args: &Args) -> Result<tokio::fs::File> {
    if let Some(output_path) = &args.output {
        let file = tokio::fs::File::create(output_path).await?;
        Ok(file)
    } else {
        let _stdout = tokio::io::stdout();
        // For stdout, we'll write a temp file and copy to stdout
        let temp_file = tokio::fs::File::create("/tmp/qdns_output.tmp").await?;
        Ok(temp_file)
    }
}
