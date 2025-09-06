use crate::cli::Args;
use crate::packet::{DnsPacket, QueryResult, next_query_id};
use crate::sharding::{SocketShardPool, calculate_optimal_shards};
use anyhow::Result;
use dashmap::DashMap;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::mpsc,
    task::JoinHandle,
};
use trust_dns_proto::{rr::RecordType, op::ResponseCode};

/// Resolver health tracking for adaptive concurrency and failure handling
#[derive(Debug, Clone)]
pub struct ResolverHealth {
    pub success_count: u64,
    pub failure_count: u64,
    pub timeout_count: u64,
    pub avg_response_time: Duration,
    pub last_updated: Instant,
    pub health_score: f64,
    pub is_healthy: bool,
}

impl ResolverHealth {
    pub fn new() -> Self {
        Self {
            success_count: 0,
            failure_count: 0,
            timeout_count: 0,
            avg_response_time: Duration::from_millis(100),
            last_updated: Instant::now(),
            health_score: 1.0,
            is_healthy: true,
        }
    }

    pub fn update_success(&mut self, response_time: Duration) {
        self.success_count += 1;
        // Exponential moving average for response time
        self.avg_response_time = Duration::from_millis(
            ((self.avg_response_time.as_millis() as f64 * 0.9) + 
             (response_time.as_millis() as f64 * 0.1)) as u64
        );
        self.last_updated = Instant::now();
        self.recalculate_health();
    }

    pub fn update_failure(&mut self) {
        self.failure_count += 1;
        self.last_updated = Instant::now();
        self.recalculate_health();
    }

    pub fn update_timeout(&mut self) {
        self.timeout_count += 1;
        self.last_updated = Instant::now();
        self.recalculate_health();
    }

    fn recalculate_health(&mut self) {
        let total_requests = self.success_count + self.failure_count + self.timeout_count;
        if total_requests == 0 {
            self.health_score = 1.0;
            self.is_healthy = true;
            return;
        }

        let success_rate = self.success_count as f64 / total_requests as f64;
        let response_time_factor = 1.0 - (self.avg_response_time.as_millis() as f64 / 5000.0).min(1.0);
        
        // Health score combines success rate (80%) and response time (20%)
        self.health_score = (success_rate * 0.8 + response_time_factor * 0.2).max(0.0).min(1.0);
        
        // Resolver is healthy if score > 0.5, or if new (< 100 requests) and score > 0.3
        self.is_healthy = if total_requests < 100 {
            self.health_score > 0.3
        } else {
            self.health_score > 0.5
        };
    }

    pub fn get_adaptive_concurrency(&self, base_concurrency: usize) -> usize {
        let factor = if self.is_healthy {
            // Healthy resolvers get 1.0x to 2.0x concurrency based on health score
            (self.health_score * 1.5).min(2.0)
        } else {
            // Unhealthy resolvers get reduced concurrency
            0.2
        };
        ((base_concurrency as f64 * factor) as usize).max(1).min(base_concurrency * 2)
    }
}

/// High-performance DNS resolution engine with socket sharding
pub struct DnsEngine {
    args: Args,
    record_type: RecordType,
    stats: Arc<EngineStats>,
    outstanding_queries: Arc<DashMap<u16, OutstandingQuery>>,
    socket_pool: Arc<SocketShardPool>,
    resolver_health: Arc<Mutex<HashMap<usize, ResolverHealth>>>,
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
    resolver_index: usize,
    start_time: Instant,
    retries_left: u32,
    result_sender: mpsc::UnboundedSender<QueryResult>,
    original_id: u16,
    attempted_resolvers: Vec<usize>,
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
        
        // Initialize resolver health tracking
        let mut resolver_health = HashMap::new();
        for i in 0..args.resolvers.len() {
            resolver_health.insert(i, ResolverHealth::new());
        }
        
        Ok(Self {
            args,
            record_type,
            stats: Arc::new(EngineStats::default()),
            outstanding_queries: Arc::new(DashMap::new()),
            socket_pool,
            resolver_health: Arc::new(Mutex::new(resolver_health)),
        })
    }

    /// Select the best available resolver based on health and attempted resolvers
    fn select_best_resolver(&self, attempted_resolvers: &[usize]) -> usize {
        let health_map = self.resolver_health.lock().unwrap();
        let mut best_index = 0;
        let mut best_score = -1.0;
        
        for (i, health) in health_map.iter() {
            // Skip already attempted resolvers
            if attempted_resolvers.contains(i) {
                continue;
            }
            
            let score = if health.is_healthy {
                health.health_score
            } else {
                // Give unhealthy resolvers a very low score but not zero
                // to allow them to recover
                health.health_score * 0.1
            };
            
            if score > best_score {
                best_score = score;
                best_index = *i;
            }
        }
        
        // If all resolvers have been attempted, start over with the healthiest
        if best_score < 0.0 {
            best_index = health_map.iter()
                .max_by(|(_, a), (_, b)| a.health_score.partial_cmp(&b.health_score).unwrap())
                .map(|(i, _)| *i)
                .unwrap_or(0);
        }
        
        best_index
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
        let resolver_health = self.resolver_health.clone();

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

                        let task = Self::spawn_single_query_static(
                            domain,
                            record_type,
                            result_sender.clone(),
                            permit,
                            args.clone(),
                            stats.clone(),
                            outstanding_queries.clone(),
                            socket_pool.clone(),
                            resolver_health.clone(),
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

    /// Spawn a single query task (static version for use in async closures)
    fn spawn_single_query_static(
        domain: String,
        record_type: RecordType,
        result_sender: mpsc::UnboundedSender<QueryResult>,
        _permit: tokio::sync::OwnedSemaphorePermit,
        args: Args,
        stats: Arc<EngineStats>,
        outstanding_queries: Arc<DashMap<u16, OutstandingQuery>>,
        socket_pool: Arc<SocketShardPool>,
        resolver_health: Arc<Mutex<HashMap<usize, ResolverHealth>>>,
    ) -> JoinHandle<()> {

        tokio::spawn(async move {
            // Select best resolver based on health (initially empty attempted list)
            let attempted_resolvers = Vec::new();
            let resolver_idx = {
                let health_map = resolver_health.lock().unwrap();
                let mut best_index = 0;
                let mut best_score = -1.0;
                
                for (i, health) in health_map.iter() {
                    let score = if health.is_healthy {
                        health.health_score
                    } else {
                        health.health_score * 0.1
                    };
                    
                    if score > best_score {
                        best_score = score;
                        best_index = *i;
                    }
                }
                best_index
            };
            
            let resolver = args.resolvers[resolver_idx];

            // Select socket shard for this query
            let shard = socket_pool.get_shard();
            
            match Self::send_query_with_retries(
                domain.clone(),
                record_type,
                resolver,
                resolver_idx,
                &shard.socket,
                &outstanding_queries,
                &result_sender,
                &stats,
                args.retries,
                attempted_resolvers,
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
        resolver_index: usize,
        socket: &Arc<tokio::net::UdpSocket>,
        outstanding_queries: &Arc<DashMap<u16, OutstandingQuery>>,
        result_sender: &mpsc::UnboundedSender<QueryResult>,
        stats: &Arc<EngineStats>,
        max_retries: u32,
        mut attempted_resolvers: Vec<usize>,
    ) -> Result<()> {
        let packet = DnsPacket::new(domain.clone(), record_type, resolver);
        let query_data = packet.build_query()?;
        
        // Add this resolver to attempted list
        attempted_resolvers.push(resolver_index);
        
        // Track the outstanding query
        let outstanding = OutstandingQuery {
            domain: packet.domain.clone(),
            record_type: packet.record_type,
            resolver: packet.resolver,
            resolver_index,
            start_time: Instant::now(),
            retries_left: max_retries,
            result_sender: result_sender.clone(),
            original_id: packet.id,
            attempted_resolvers,
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
        let socket_pool = self.socket_pool.clone();
        let resolver_health = self.resolver_health.clone();

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
                            &socket_pool,
                            &resolver_health,
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
        args: &Args,
        socket_pool: &Arc<SocketShardPool>,
        resolver_health: &Arc<Mutex<HashMap<usize, ResolverHealth>>>,
    ) -> Result<()> {
        let response = crate::packet::DnsPacket::parse_response(data)?;
        
        if let Some((_, outstanding)) = outstanding_queries.remove(&response.id) {
            let elapsed = outstanding.start_time.elapsed();
            let elapsed_ms = elapsed.as_millis() as u64;
            
            stats.responses_received.fetch_add(1, Ordering::Relaxed);
            stats.in_flight.fetch_sub(1, Ordering::Relaxed);
            
            let domain_clone = outstanding.domain.clone();
            let response_id = response.id;
            let resolver_idx = outstanding.resolver_index;
            
            let result = if response.is_success() {
                // Update resolver health with success
                {
                    let mut health_map = resolver_health.lock().unwrap();
                    if let Some(health) = health_map.get_mut(&resolver_idx) {
                        health.update_success(elapsed);
                    }
                }
                
                stats.successful_resolutions.fetch_add(1, Ordering::Relaxed);
                QueryResult::success(
                    outstanding.domain,
                    outstanding.record_type,
                    outstanding.resolver,
                    response,
                    elapsed_ms,
                )
            } else {
                // Update resolver health with failure
                {
                    let mut health_map = resolver_health.lock().unwrap();
                    if let Some(health) = health_map.get_mut(&resolver_idx) {
                        health.update_failure();
                    }
                }
                // Check if we should retry based on response code
                let should_retry = match response.response_code {
                    ResponseCode::ServFail |
                    ResponseCode::Refused |
                    ResponseCode::FormErr => true,
                    _ => false,
                };

                if should_retry && outstanding.retries_left > 0 {
                    // Select best resolver based on health and attempted resolvers
                    let next_resolver_index = {
                        let health_map = resolver_health.lock().unwrap();
                        let mut best_index = 0;
                        let mut best_score = -1.0;
                        
                        for (i, health) in health_map.iter() {
                            // Skip already attempted resolvers
                            if outstanding.attempted_resolvers.contains(i) {
                                continue;
                            }
                            
                            let score = if health.is_healthy {
                                health.health_score
                            } else {
                                health.health_score * 0.1
                            };
                            
                            if score > best_score {
                                best_score = score;
                                best_index = *i;
                            }
                        }
                        
                        // If all resolvers have been attempted, start over with the healthiest
                        if best_score < 0.0 {
                            best_index = health_map.iter()
                                .max_by(|(_, a), (_, b)| a.health_score.partial_cmp(&b.health_score).unwrap())
                                .map(|(i, _)| *i)
                                .unwrap_or(0);
                        }
                        
                        best_index
                    };
                    
                    let next_resolver = args.resolvers[next_resolver_index];
                    
                    // Create retry query with new ID and different resolver
                    let retry_id = next_query_id();
                    let mut new_attempted = outstanding.attempted_resolvers.clone();
                    new_attempted.push(next_resolver_index);
                    
                    let retry_outstanding = OutstandingQuery {
                        domain: outstanding.domain.clone(),
                        record_type: outstanding.record_type,
                        resolver: next_resolver,
                        resolver_index: next_resolver_index,
                        start_time: Instant::now(), // Reset timer for retry
                        retries_left: outstanding.retries_left - 1,
                        result_sender: outstanding.result_sender.clone(),
                        original_id: outstanding.original_id,
                        attempted_resolvers: new_attempted,
                    };
                    
                    // Build and send the retry query
                    match Self::send_retry_query(
                        retry_outstanding.domain.clone(),
                        retry_outstanding.record_type,
                        next_resolver,
                        retry_id,
                    ).await {
                        Ok(query_data) => {
                            // Track the retry query
                            outstanding_queries.insert(retry_id, retry_outstanding);
                            stats.retries.fetch_add(1, Ordering::Relaxed);
                            stats.in_flight.fetch_add(1, Ordering::Relaxed);
                            
                            // Send the query using a socket from the pool
                            let shard = socket_pool.get_shard();
                            if shard.socket.send_to(&query_data, next_resolver).await.is_ok() {
                                // Retry was successful, don't send error result yet
                                return Ok(());
                            } else {
                                // Failed to send retry, clean up and proceed to error result
                                outstanding_queries.remove(&retry_id);
                                stats.in_flight.fetch_sub(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
                            // Failed to build retry query, proceed to error result
                        }
                    }
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

    /// Build query packet for retry
    async fn send_retry_query(
        domain: String,
        record_type: RecordType,
        resolver: SocketAddr,
        query_id: u16,
    ) -> Result<Vec<u8>> {
        let mut packet = crate::packet::DnsPacket::new(domain, record_type, resolver);
        packet.id = query_id; // Use the provided retry ID
        let bytes = packet.build_query()?;
        Ok(bytes.to_vec())
    }

    /// Spawn timeout handler
    fn spawn_timeout_handler(&self) -> JoinHandle<()> {
        let outstanding_queries = self.outstanding_queries.clone();
        let stats = self.stats.clone();
        let args = self.args.clone();
        let socket_pool = self.socket_pool.clone();
        let resolver_health = self.resolver_health.clone();
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
                        // Update resolver health with timeout
                        {
                            let mut health_map = resolver_health.lock().unwrap();
                            if let Some(health) = health_map.get_mut(&outstanding.resolver_index) {
                                health.update_timeout();
                            }
                        }
                        
                        stats.timeouts.fetch_add(1, Ordering::Relaxed);
                        stats.in_flight.fetch_sub(1, Ordering::Relaxed);
                        
                        // Try retry with different resolver if retries are available
                        if outstanding.retries_left > 0 {
                            // Select best resolver based on health and attempted resolvers
                            let next_resolver_index = {
                                let health_map = resolver_health.lock().unwrap();
                                let mut best_index = 0;
                                let mut best_score = -1.0;
                                
                                for (i, health) in health_map.iter() {
                                    if outstanding.attempted_resolvers.contains(i) {
                                        continue;
                                    }
                                    
                                    let score = if health.is_healthy {
                                        health.health_score
                                    } else {
                                        health.health_score * 0.1
                                    };
                                    
                                    if score > best_score {
                                        best_score = score;
                                        best_index = *i;
                                    }
                                }
                                
                                if best_score < 0.0 {
                                    best_index = health_map.iter()
                                        .max_by(|(_, a), (_, b)| a.health_score.partial_cmp(&b.health_score).unwrap())
                                        .map(|(i, _)| *i)
                                        .unwrap_or(0);
                                }
                                
                                best_index
                            };
                            
                            let next_resolver = args.resolvers[next_resolver_index];
                            
                            let retry_id = next_query_id();
                            let mut new_attempted = outstanding.attempted_resolvers.clone();
                            new_attempted.push(next_resolver_index);
                            
                            let retry_outstanding = OutstandingQuery {
                                domain: outstanding.domain.clone(),
                                record_type: outstanding.record_type,
                                resolver: next_resolver,
                                resolver_index: next_resolver_index,
                                start_time: Instant::now(),
                                retries_left: outstanding.retries_left - 1,
                                result_sender: outstanding.result_sender.clone(),
                                original_id: outstanding.original_id,
                                attempted_resolvers: new_attempted,
                            };
                            
                            // Try to send retry query
                            match Self::send_retry_query(
                                retry_outstanding.domain.clone(),
                                retry_outstanding.record_type,
                                next_resolver,
                                retry_id,
                            ).await {
                                Ok(query_data) => {
                                    // Track the retry query
                                    outstanding_queries.insert(retry_id, retry_outstanding);
                                    stats.retries.fetch_add(1, Ordering::Relaxed);
                                    stats.in_flight.fetch_add(1, Ordering::Relaxed);
                                    
                                    // Send the query
                                    let shard = socket_pool.get_shard();
                                    if shard.socket.send_to(&query_data, next_resolver).await.is_ok() {
                                        // Retry was successful, continue without sending error
                                        continue;
                                    } else {
                                        // Failed to send retry, clean up and proceed to timeout error
                                        outstanding_queries.remove(&retry_id);
                                        stats.in_flight.fetch_sub(1, Ordering::Relaxed);
                                    }
                                }
                                Err(_) => {
                                    // Failed to build retry query, proceed to timeout error
                                }
                            }
                        }
                        
                        // No retries left or retry failed, send timeout error
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
        let resolver_health = self.resolver_health.clone();
        let args = self.args.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            
            loop {
                interval.tick().await;
                
                let sent = stats.queries_sent.load(Ordering::Relaxed);
                let received = stats.responses_received.load(Ordering::Relaxed);
                let successful = stats.successful_resolutions.load(Ordering::Relaxed);
                let timeouts = stats.timeouts.load(Ordering::Relaxed);
                let retries = stats.retries.load(Ordering::Relaxed);
                let in_flight = stats.in_flight.load(Ordering::Relaxed);
                let malformed = stats.malformed_domains.load(Ordering::Relaxed);
                
                tracing::info!(
                    "📊 Stats: sent={}, received={}, successful={}, timeouts={}, retries={}, in_flight={}, malformed={}",
                    sent, received, successful, timeouts, retries, in_flight, malformed
                );
                
                // Log resolver health summary
                {
                    let health_map = resolver_health.lock().unwrap();
                    let healthy_count = health_map.values().filter(|h| h.is_healthy).count();
                    let total_resolvers = args.resolvers.len();
                    
                    tracing::info!(
                        "🏥 Resolver Health: {}/{} healthy resolvers", 
                        healthy_count, total_resolvers
                    );
                    
                    // Log top 5 healthiest and worst resolvers
                    let mut sorted_health: Vec<_> = health_map.iter().collect();
                    sorted_health.sort_by(|a, b| b.1.health_score.partial_cmp(&a.1.health_score).unwrap());
                    
                    for (i, (idx, health)) in sorted_health.iter().take(3).enumerate() {
                        let resolver = args.resolvers[**idx];
                        tracing::debug!(
                            "Top {}: {} (score: {:.2}, success: {}, timeouts: {}, avg_ms: {})",
                            i + 1, resolver, health.health_score, health.success_count,
                            health.timeout_count, health.avg_response_time.as_millis()
                        );
                    }
                }
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

    /// Get resolver health summary for final reporting
    pub fn get_resolver_health_summary(&self) -> Vec<(SocketAddr, ResolverHealth)> {
        let health_map = self.resolver_health.lock().unwrap();
        let mut summary = Vec::new();
        
        for (idx, health) in health_map.iter() {
            if *idx < self.args.resolvers.len() {
                let resolver = self.args.resolvers[*idx];
                summary.push((resolver, health.clone()));
            }
        }
        
        // Sort by health score descending
        summary.sort_by(|a, b| b.1.health_score.partial_cmp(&a.1.health_score).unwrap());
        summary
    }
}