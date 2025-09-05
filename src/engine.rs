use crate::cli::Args;
use crate::packet::{DnsPacket, QueryResult, next_query_id};
use crate::sharding::{SocketShardPool, calculate_optimal_shards};
use anyhow::Result;
use dashmap::DashMap;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::mpsc,
    task::JoinHandle,
};
use trust_dns_proto::rr::RecordType;

/// High-performance DNS resolution engine with socket sharding
pub struct DnsEngine {
    args: Args,
    record_type: RecordType,
    stats: Arc<EngineStats>,
    outstanding_queries: Arc<DashMap<u16, OutstandingQuery>>,
    socket_pool: Arc<SocketShardPool>,
}

/// Statistics for the DNS engine
#[derive(Debug, Default)]
pub struct EngineStats {
    pub queries_sent: AtomicU64,
    pub responses_received: AtomicU64,
    pub successful_resolutions: AtomicU64,
    pub timeouts: AtomicU64,
    pub retries: AtomicU64,
    pub in_flight: AtomicUsize,
    pub malformed_domains: AtomicU64,
}

/// Outstanding query tracking with retry logic
#[derive(Debug)]
struct OutstandingQuery {
    domain: String,
    record_type: RecordType,
    resolver: SocketAddr,
    start_time: Instant,
    retries_left: u32,
    result_sender: mpsc::UnboundedSender<QueryResult>,
    original_id: u16,
}

impl DnsEngine {
    /// Create a new high-performance DNS engine
    pub async fn new(args: Args, record_type: RecordType) -> Result<Self> {
        let concurrency = args.get_concurrency();
        
        // Calculate optimal number of socket shards
        let num_shards = calculate_optimal_shards(concurrency);
        tracing::info!("🔧 Creating {} socket shards for {} concurrency", num_shards, concurrency);
        
        // Create socket shard pool
        let socket_pool = Arc::new(SocketShardPool::new(num_shards, None).await?);
        
        Ok(Self {
            args,
            record_type,
            stats: Arc::new(EngineStats::default()),
            outstanding_queries: Arc::new(DashMap::new()),
            socket_pool,
        })
    }

    /// Start the DNS resolution engine with sliding window concurrency
    pub async fn run(&self, domains: Vec<String>) -> Result<mpsc::UnboundedReceiver<QueryResult>> {
        let (result_sender, result_receiver) = mpsc::unbounded_channel();
        let concurrency = self.args.get_concurrency();
        
        tracing::info!(
            "🚀 Starting DNS engine: {} domains, {} resolvers, {} concurrency, {} shards",
            domains.len(),
            self.args.resolvers.len(),
            concurrency,
            self.socket_pool.num_shards()
        );

        // Start receiver tasks for each socket shard
        let mut receiver_handles = Vec::new();
        for shard in self.socket_pool.get_all_shards() {
            let handle = self.spawn_receiver_task(shard.socket.clone(), shard.shard_id);
            receiver_handles.push(handle);
        }

        // Start timeout handler
        let timeout_handle = self.spawn_timeout_handler();
        receiver_handles.push(timeout_handle);

        // Start query processor with sliding window
        let query_handle = self.spawn_query_processor(domains, result_sender.clone(), concurrency);
        receiver_handles.push(query_handle);

        // Start stats reporter if verbose
        if self.args.verbose {
            let stats_handle = self.spawn_stats_reporter();
            receiver_handles.push(stats_handle);
        }

        // Spawn cleanup task to wait for all workers
        tokio::spawn(async move {
            futures::future::join_all(receiver_handles).await;
            tracing::debug!("All engine tasks completed");
        });

        Ok(result_receiver)
    }

    /// Spawn query processor with sliding window concurrency control
    fn spawn_query_processor(
        &self,
        domains: Vec<String>,
        result_sender: mpsc::UnboundedSender<QueryResult>,
        max_concurrency: usize,
    ) -> JoinHandle<()> {
        let args = self.args.clone();
        let record_type = self.record_type;
        let stats = self.stats.clone();
        let outstanding_queries = self.outstanding_queries.clone();
        let socket_pool = self.socket_pool.clone();

        tokio::spawn(async move {
            let concurrency_limiter = Arc::new(tokio::sync::Semaphore::new(max_concurrency));
            let mut domain_iter = domains.into_iter();
            let mut active_tasks = Vec::new();

            // Sliding window: keep pipeline full
            loop {
                // Clean up completed tasks
                active_tasks.retain(|task: &JoinHandle<()>| !task.is_finished());

                // Fill pipeline with new queries
                while active_tasks.len() < max_concurrency {
                    if let Some(domain) = domain_iter.next() {
                        let permit = match concurrency_limiter.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => break, // Pipeline full
                        };

                        let task = Self::spawn_single_query(
                            domain,
                            record_type,
                            &args,
                            &stats,
                            &outstanding_queries,
                            &socket_pool,
                            &result_sender,
                            permit,
                        );
                        
                        active_tasks.push(task);
                    } else {
                        // No more domains to process
                        break;
                    }
                }

                // If no more domains and no active tasks, we're done
                if domain_iter.len() == 0 && active_tasks.is_empty() {
                    break;
                }

                // Wait a bit before checking again
                tokio::time::sleep(Duration::from_millis(1)).await;
            }

            // Wait for remaining tasks to complete
            futures::future::join_all(active_tasks).await;
            tracing::info!("Query processor completed");
        })
    }

    /// Spawn a single query task
    fn spawn_single_query(
        domain: String,
        record_type: RecordType,
        args: &Args,
        stats: &Arc<EngineStats>,
        outstanding_queries: &Arc<DashMap<u16, OutstandingQuery>>,
        socket_pool: &Arc<SocketShardPool>,
        result_sender: &mpsc::UnboundedSender<QueryResult>,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) -> JoinHandle<()> {
        let args = args.clone();
        let stats = stats.clone();
        let outstanding_queries = outstanding_queries.clone();
        let socket_pool = socket_pool.clone();
        let result_sender = result_sender.clone();

        tokio::spawn(async move {
            // Try each resolver in round-robin
            let resolver_idx = stats.queries_sent.load(Ordering::Relaxed) as usize % args.resolvers.len();
            let resolver = args.resolvers[resolver_idx];

            // Select socket shard for this query
            let shard = socket_pool.get_shard();
            
            match Self::send_query_with_retries(
                domain.clone(),
                record_type,
                resolver,
                &shard.socket,
                &outstanding_queries,
                &result_sender,
                &stats,
                args.retries,
            ).await {
                Ok(_) => {
                    stats.queries_sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::debug!("Failed to send query for {}: {}", domain, e);
                    stats.malformed_domains.fetch_add(1, Ordering::Relaxed);
                    
                    let result = QueryResult::error(
                        domain,
                        record_type,
                        resolver,
                        e.to_string(),
                        0,
                    );
                    let _ = result_sender.send(result);
                }
            }

            // Rate limiting
            if args.rate_limit > 0 {
                let delay_ms = 1000 / args.rate_limit as u64;
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
            }
            
            // _permit is automatically dropped here, releasing semaphore
        })
    }

    /// Send query with automatic retries
    async fn send_query_with_retries(
        domain: String,
        record_type: RecordType,
        resolver: SocketAddr,
        socket: &Arc<tokio::net::UdpSocket>,
        outstanding_queries: &Arc<DashMap<u16, OutstandingQuery>>,
        result_sender: &mpsc::UnboundedSender<QueryResult>,
        stats: &Arc<EngineStats>,
        max_retries: u32,
    ) -> Result<()> {
        let packet = DnsPacket::new(domain.clone(), record_type, resolver);
        let query_data = packet.build_query()?;
        
        // Track the outstanding query
        let outstanding = OutstandingQuery {
            domain: packet.domain.clone(),
            record_type: packet.record_type,
            resolver: packet.resolver,
            start_time: Instant::now(),
            retries_left: max_retries,
            result_sender: result_sender.clone(),
            original_id: packet.id,
        };
        
        outstanding_queries.insert(packet.id, outstanding);
        stats.in_flight.fetch_add(1, Ordering::Relaxed);
        
        // Send the query
        socket.send_to(&query_data, packet.resolver).await?;
        
        tracing::trace!("Sent query {} to {} for {}", packet.id, packet.resolver, packet.domain);
        
        Ok(())
    }

    /// Spawn receiver task for a socket shard
    fn spawn_receiver_task(
        &self,
        socket: Arc<tokio::net::UdpSocket>,
        shard_id: usize,
    ) -> JoinHandle<()> {
        let outstanding_queries = self.outstanding_queries.clone();
        let stats = self.stats.clone();
        let args = self.args.clone();

        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            
            tracing::debug!("Receiver task {} started", shard_id);
            
            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((len, _src)) => {
                        if let Err(e) = Self::handle_response(
                            &buffer[..len],
                            &outstanding_queries,
                            &stats,
                            &args,
                        ).await {
                            tracing::warn!("Failed to handle response on shard {}: {}", shard_id, e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Socket {} receive error: {}", shard_id, e);
                        break;
                    }
                }
            }
        })
    }

    /// Handle DNS response with retry logic
    async fn handle_response(
        data: &[u8],
        outstanding_queries: &Arc<DashMap<u16, OutstandingQuery>>,
        stats: &Arc<EngineStats>,
        _args: &Args,
    ) -> Result<()> {
        let response = crate::packet::DnsPacket::parse_response(data)?;
        
        if let Some((_, outstanding)) = outstanding_queries.remove(&response.id) {
            let elapsed = outstanding.start_time.elapsed();
            let elapsed_ms = elapsed.as_millis() as u64;
            
            stats.responses_received.fetch_add(1, Ordering::Relaxed);
            stats.in_flight.fetch_sub(1, Ordering::Relaxed);
            
            let domain_clone = outstanding.domain.clone();
            let response_id = response.id;
            
            let result = if response.is_success() {
                stats.successful_resolutions.fetch_add(1, Ordering::Relaxed);
                QueryResult::success(
                    outstanding.domain,
                    outstanding.record_type,
                    outstanding.resolver,
                    response,
                    elapsed_ms,
                )
            } else {
                // Check if we should retry
                if outstanding.retries_left > 0 {
                    stats.retries.fetch_add(1, Ordering::Relaxed);
                    
                    // Create retry query with new ID
                    let retry_id = next_query_id();
                    let retry_outstanding = OutstandingQuery {
                        domain: outstanding.domain.clone(),
                        record_type: outstanding.record_type,
                        resolver: outstanding.resolver,
                        start_time: outstanding.start_time,
                        retries_left: outstanding.retries_left - 1,
                        result_sender: outstanding.result_sender.clone(),
                        original_id: outstanding.original_id,
                    };
                    
                    outstanding_queries.insert(retry_id, retry_outstanding);
                    
                    // Note: The actual retry sending would need to be implemented
                    // For now, just treat as error
                }
                
                QueryResult::error(
                    outstanding.domain,
                    outstanding.record_type,
                    outstanding.resolver,
                    format!("DNS error: {:?}", response.response_code),
                    elapsed_ms,
                )
            };
            
            let _ = outstanding.result_sender.send(result);
            
            tracing::trace!(
                "Handled response {} for {} in {}ms",
                response_id,
                domain_clone,
                elapsed_ms
            );
        } else {
            tracing::debug!("Received response for unknown query ID: {}", response.id);
        }
        
        Ok(())
    }

    /// Spawn timeout handler
    fn spawn_timeout_handler(&self) -> JoinHandle<()> {
        let outstanding_queries = self.outstanding_queries.clone();
        let stats = self.stats.clone();
        let timeout_duration = Duration::from_millis(self.args.timeout);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            
            loop {
                interval.tick().await;
                
                let now = Instant::now();
                let mut timed_out = Vec::new();
                
                // Find timed out queries
                for entry in outstanding_queries.iter() {
                    let query_id = *entry.key();
                    let outstanding = entry.value();
                    
                    if now.duration_since(outstanding.start_time) > timeout_duration {
                        timed_out.push(query_id);
                    }
                }
                
                // Handle timeouts
                for query_id in timed_out {
                    if let Some((_, outstanding)) = outstanding_queries.remove(&query_id) {
                        stats.timeouts.fetch_add(1, Ordering::Relaxed);
                        stats.in_flight.fetch_sub(1, Ordering::Relaxed);
                        
                        let elapsed_ms = outstanding.start_time.elapsed().as_millis() as u64;
                        
                        let result = QueryResult::error(
                            outstanding.domain,
                            outstanding.record_type,
                            outstanding.resolver,
                            "Timeout".to_string(),
                            elapsed_ms,
                        );
                        
                        let _ = outstanding.result_sender.send(result);
                    }
                }
            }
        })
    }

    /// Spawn stats reporter
    fn spawn_stats_reporter(&self) -> JoinHandle<()> {
        let stats = self.stats.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            
            loop {
                interval.tick().await;
                
                let sent = stats.queries_sent.load(Ordering::Relaxed);
                let received = stats.responses_received.load(Ordering::Relaxed);
                let successful = stats.successful_resolutions.load(Ordering::Relaxed);
                let timeouts = stats.timeouts.load(Ordering::Relaxed);
                let in_flight = stats.in_flight.load(Ordering::Relaxed);
                let malformed = stats.malformed_domains.load(Ordering::Relaxed);
                
                tracing::info!(
                    "📊 Stats: sent={}, received={}, successful={}, timeouts={}, in_flight={}, malformed={}",
                    sent, received, successful, timeouts, in_flight, malformed
                );
            }
        })
    }

    /// Get final statistics
    pub fn get_stats(&self) -> EngineStats {
        EngineStats {
            queries_sent: AtomicU64::new(self.stats.queries_sent.load(Ordering::Relaxed)),
            responses_received: AtomicU64::new(self.stats.responses_received.load(Ordering::Relaxed)),
            successful_resolutions: AtomicU64::new(self.stats.successful_resolutions.load(Ordering::Relaxed)),
            timeouts: AtomicU64::new(self.stats.timeouts.load(Ordering::Relaxed)),
            retries: AtomicU64::new(self.stats.retries.load(Ordering::Relaxed)),
            in_flight: AtomicUsize::new(self.stats.in_flight.load(Ordering::Relaxed)),
            malformed_domains: AtomicU64::new(self.stats.malformed_domains.load(Ordering::Relaxed)),
        }
    }
}