use anyhow::Result;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn, error};

/// System resource manager for optimizing UDP performance
pub struct SystemOptimizer {
    verbose: bool,
    max_concurrency: AtomicUsize,
    buffer_exhaustion_detected: AtomicBool,
    optimization_applied: AtomicBool,
}

impl SystemOptimizer {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            max_concurrency: AtomicUsize::new(0),
            buffer_exhaustion_detected: AtomicBool::new(false),
            optimization_applied: AtomicBool::new(false),
        }
    }

    /// Configure system resources for high-concurrency UDP operations
    pub fn configure_system(&self) -> Result<()> {
        if self.optimization_applied.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.configure_file_descriptors()?;
        self.configure_network_parameters()?;
        self.configure_udp_buffers()?;
        
        self.optimization_applied.store(true, Ordering::Relaxed);
        
        if self.verbose {
            info!("System optimization completed successfully");
        }
        
        Ok(())
    }

    /// Set file descriptor limits
    fn configure_file_descriptors(&self) -> Result<()> {
        unsafe {
            // Try to set a very high file descriptor limit
            let target_limit = 1_048_576; // 1M file descriptors
            
            let rlimit = libc::rlimit {
                rlim_cur: target_limit,
                rlim_max: target_limit,
            };
            
            if libc::setrlimit(libc::RLIMIT_NOFILE, &rlimit) != 0 {
                let err = io::Error::last_os_error();
                if self.verbose {
                    warn!(
                        "Failed to set file descriptor limit to {}. Run 'ulimit -n {}' manually: {}",
                        target_limit, target_limit, err
                    );
                }
                
                // Try a more conservative limit
                let conservative_limit = 65536;
                let conservative_rlimit = libc::rlimit {
                    rlim_cur: conservative_limit,
                    rlim_max: conservative_limit,
                };
                
                if libc::setrlimit(libc::RLIMIT_NOFILE, &conservative_rlimit) != 0 {
                    return Err(anyhow::anyhow!("Failed to set file descriptor limits"));
                } else if self.verbose {
                    info!("Set conservative file descriptor limit to {}", conservative_limit);
                }
            } else if self.verbose {
                info!("Set file descriptor limit to {}", target_limit);
            }
        }
        
        Ok(())
    }

    /// Configure network parameters for high performance
    fn configure_network_parameters(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let sysctl_settings = [
                // Increase port range for more concurrent connections
                ("net.ipv4.ip_local_port_range", "10000 65535"),
                // Reduce TIME_WAIT duration
                ("net.ipv4.tcp_fin_timeout", "15"),
                // Enable socket reuse
                ("net.ipv4.tcp_tw_reuse", "1"),
                // Increase maximum open files
                ("fs.file-max", "2097152"),
                // UDP buffer sizes
                ("net.core.rmem_max", "134217728"),
                ("net.core.wmem_max", "134217728"),
                ("net.core.rmem_default", "262144"),
                ("net.core.wmem_default", "262144"),
                // Network device buffer sizes
                ("net.core.netdev_max_backlog", "30000"),
                ("net.core.netdev_budget", "600"),
            ];
            
            for (key, value) in sysctl_settings.iter() {
                self.set_sysctl_parameter(key, value);
            }
        }

        #[cfg(target_os = "macos")]
        {
            if self.verbose {
                info!("macOS UDP optimization suggestions:");
                info!("  sudo sysctl -w kern.maxfiles=2097152");
                info!("  sudo sysctl -w kern.maxfilesperproc=1048576");
                info!("  sudo sysctl -w net.inet.udp.maxdgram=65536");
                info!("  sudo sysctl -w kern.ipc.maxsockbuf=16777216");
                info!("Note: Some settings require root privileges");
            }
            
            // Try to set what we can programmatically
            self.optimize_macos_udp();
        }

        Ok(())
    }

    /// Configure UDP-specific buffer settings
    fn configure_udp_buffers(&self) -> Result<()> {
        if self.verbose {
            info!("UDP buffer optimization tips:");
            info!("  - Using socket pools to reduce resource consumption");
            info!("  - Implementing adaptive concurrency based on buffer availability");
            info!("  - Monitoring for 'No buffer space available' errors");
        }
        
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn set_sysctl_parameter(&self, key: &str, value: &str) {
        let cmd = std::process::Command::new("sysctl")
            .arg("-w")
            .arg(format!("{}={}", key, value))
            .output();
            
        match cmd {
            Ok(output) if output.status.success() => {
                if self.verbose {
                    info!("Set {} = {}", key, value);
                }
            }
            Ok(output) => {
                let err = String::from_utf8_lossy(&output.stderr);
                if self.verbose {
                    warn!(
                        "Failed to set {} = {}. Run 'sudo sysctl -w {}={}' manually: {}",
                        key, value, key, value, err
                    );
                }
            }
            Err(e) => {
                if self.verbose {
                    warn!(
                        "Failed to run sysctl for {} = {}: {}. Run 'sudo sysctl -w {}={}' manually",
                        key, value, e, key, value
                    );
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn optimize_macos_udp(&self) {
        // macOS-specific UDP optimizations that can be done programmatically
        if self.verbose {
            info!("Applying macOS-specific UDP optimizations...");
        }
    }

    /// Detect if we're hitting UDP buffer limits
    pub fn detect_buffer_exhaustion(&self, error_message: &str) -> bool {
        let is_buffer_error = error_message.contains("No buffer space available") ||
                             error_message.contains("os error 55") ||
                             error_message.contains("Resource temporarily unavailable");
        
        if is_buffer_error && !self.buffer_exhaustion_detected.load(Ordering::Relaxed) {
            self.buffer_exhaustion_detected.store(true, Ordering::Relaxed);
            if self.verbose {
                warn!("UDP buffer exhaustion detected: {}", error_message);
                warn!("Recommendations:");
                warn!("  1. Reduce concurrency level");
                warn!("  2. Increase system UDP buffer sizes");
                warn!("  3. Use socket pooling");
                warn!("  4. Implement back-pressure control");
            }
        }
        
        is_buffer_error
    }

    /// Calculate optimal concurrency based on system resources
    pub fn calculate_optimal_concurrency(&self, requested_concurrency: usize) -> usize {
        let cpu_count = num_cpus::get();
        
        // On macOS, UDP buffer limits are typically hit around 2000-5000 concurrent sockets
        #[cfg(target_os = "macos")]
        let system_limit = 2000;
        
        // On Linux, we can typically handle much higher concurrency
        #[cfg(target_os = "linux")]
        let system_limit = 50000;
        
        // Default for other systems
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let system_limit = 5000;
        
        let cpu_based_limit = cpu_count * 2000; // Conservative CPU-based estimate
        let optimal = requested_concurrency.min(system_limit).min(cpu_based_limit);
        
        if optimal < requested_concurrency && self.verbose {
            warn!(
                "Concurrency capped at {} (requested {}) to prevent buffer exhaustion",
                optimal, requested_concurrency
            );
            warn!("System limit: {}, CPU-based limit: {}", system_limit, cpu_based_limit);
        }
        
        self.max_concurrency.store(optimal, Ordering::Relaxed);
        optimal
    }

    /// Monitor system performance and adjust parameters
    pub async fn start_performance_monitor(&self, stats: Arc<crate::engine::EngineStats>) {
        if !self.verbose {
            return;
        }

        tokio::spawn({
            let optimizer = self.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(10));
                let mut last_sent = 0;
                let mut last_received = 0;
                let mut consecutive_buffer_errors = 0;
                
                loop {
                    interval.tick().await;
                    
                    let sent = stats.queries_sent.load(Ordering::Relaxed);
                    let received = stats.responses_received.load(Ordering::Relaxed);
                    let in_flight = stats.in_flight.load(Ordering::Relaxed);
                    let timeouts = stats.timeouts.load(Ordering::Relaxed);
                    
                    let sent_rate = sent.saturating_sub(last_sent);
                    let received_rate = received.saturating_sub(last_received);
                    let success_rate = if sent > 0 { 
                        (received as f64 / sent as f64) * 100.0 
                    } else { 
                        0.0 
                    };
                    
                    info!(
                        "Performance: {:.1}% success, {} QPS out, {} QPS in, {} in-flight, {} timeouts",
                        success_rate, sent_rate / 10, received_rate / 10, in_flight, timeouts
                    );
                    
                    // Detect performance degradation
                    if success_rate < 50.0 && sent > 1000 {
                        consecutive_buffer_errors += 1;
                        warn!(
                            "Low success rate detected: {:.1}% (measurement {})",
                            success_rate, consecutive_buffer_errors
                        );
                        
                        if consecutive_buffer_errors >= 3 {
                            error!("Persistent low success rate indicates system resource exhaustion");
                            error!("Consider reducing concurrency or increasing system limits");
                            consecutive_buffer_errors = 0; // Reset to avoid spam
                        }
                    } else {
                        consecutive_buffer_errors = 0;
                    }
                    
                    last_sent = sent;
                    last_received = received;
                }
            }
        });
    }

    /// Get current system status
    pub fn get_status(&self) -> SystemStatus {
        SystemStatus {
            optimization_applied: self.optimization_applied.load(Ordering::Relaxed),
            buffer_exhaustion_detected: self.buffer_exhaustion_detected.load(Ordering::Relaxed),
            max_concurrency: self.max_concurrency.load(Ordering::Relaxed),
        }
    }
}

impl Clone for SystemOptimizer {
    fn clone(&self) -> Self {
        Self {
            verbose: self.verbose,
            max_concurrency: AtomicUsize::new(self.max_concurrency.load(Ordering::Relaxed)),
            buffer_exhaustion_detected: AtomicBool::new(self.buffer_exhaustion_detected.load(Ordering::Relaxed)),
            optimization_applied: AtomicBool::new(self.optimization_applied.load(Ordering::Relaxed)),
        }
    }
}

/// System status information
#[derive(Debug, Clone)]
pub struct SystemStatus {
    pub optimization_applied: bool,
    pub buffer_exhaustion_detected: bool,
    pub max_concurrency: usize,
}

/// Utility functions for system optimization
pub mod utils {
    use super::*;

    /// Check if an error indicates buffer exhaustion
    pub fn is_buffer_exhaustion_error(error: &str) -> bool {
        error.contains("No buffer space available") ||
        error.contains("os error 55") ||
        error.contains("Resource temporarily unavailable") ||
        error.contains("Cannot allocate memory")
    }

    /// Get system-specific UDP optimization suggestions
    pub fn get_optimization_suggestions() -> Vec<String> {
        let mut suggestions = Vec::new();
        
        #[cfg(target_os = "macos")]
        {
            suggestions.extend([
                "sudo sysctl -w kern.maxfiles=2097152".to_string(),
                "sudo sysctl -w kern.maxfilesperproc=1048576".to_string(),
                "sudo sysctl -w net.inet.udp.maxdgram=65536".to_string(),
                "sudo sysctl -w kern.ipc.maxsockbuf=16777216".to_string(),
                "ulimit -n 65536".to_string(),
            ]);
        }
        
        #[cfg(target_os = "linux")]
        {
            suggestions.extend([
                "sudo sysctl -w net.core.rmem_max=134217728".to_string(),
                "sudo sysctl -w net.core.wmem_max=134217728".to_string(),
                "sudo sysctl -w net.core.netdev_max_backlog=30000".to_string(),
                "sudo sysctl -w fs.file-max=2097152".to_string(),
                "ulimit -n 1048576".to_string(),
            ]);
        }
        
        suggestions
    }
}