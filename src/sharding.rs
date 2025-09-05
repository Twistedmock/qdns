use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Socket sharding configuration for distributing load
pub struct SocketShard {
    pub socket: Arc<UdpSocket>,
    pub shard_id: usize,
}

/// Socket sharding pool with SO_REUSEPORT support
pub struct SocketShardPool {
    shards: Vec<SocketShard>,
    current_shard: std::sync::atomic::AtomicUsize,
}

impl SocketShardPool {
    /// Create a new socket shard pool
    /// 
    /// On macOS/Linux, this creates multiple sockets with SO_REUSEPORT
    /// to distribute load and bypass per-socket buffer limits.
    pub async fn new(num_shards: usize, bind_addr: Option<SocketAddr>) -> Result<Self> {
        let mut shards = Vec::with_capacity(num_shards);
        let bind_addr = bind_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        
        for shard_id in 0..num_shards {
            let socket = Self::create_shard_socket(bind_addr, shard_id).await?;
            shards.push(SocketShard {
                socket: Arc::new(socket),
                shard_id,
            });
        }
        
        Ok(Self {
            shards,
            current_shard: std::sync::atomic::AtomicUsize::new(0),
        })
    }
    
    /// Create a socket with SO_REUSEPORT if available
    async fn create_shard_socket(bind_addr: SocketAddr, shard_id: usize) -> Result<UdpSocket> {
        let socket = socket2::Socket::new(
            match bind_addr {
                SocketAddr::V4(_) => socket2::Domain::IPV4,
                SocketAddr::V6(_) => socket2::Domain::IPV6,
            },
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        
        // Enable SO_REUSEPORT on platforms that support it
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                let optval: libc::c_int = 1;
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEPORT,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                );
            }
        }
        
        // macOS uses SO_REUSEPORT differently
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                let optval: libc::c_int = 1;
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEPORT,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                );
            }
        }
        
        #[cfg(target_os = "freebsd")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = socket.as_raw_fd();
            unsafe {
                let optval: libc::c_int = 1;
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEPORT,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                );
            }
        }
        
        // Set socket options for high performance
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        
        // Set buffer sizes for high throughput
        let _ = socket.set_recv_buffer_size(1024 * 1024); // 1MB receive buffer
        let _ = socket.set_send_buffer_size(1024 * 1024); // 1MB send buffer
        
        socket.bind(&bind_addr.into())?;
        
        let tokio_socket: std::net::UdpSocket = socket.into();
        let udp_socket = UdpSocket::from_std(tokio_socket)?;
        
        tracing::debug!("Created socket shard {} bound to {}", shard_id, bind_addr);
        
        Ok(udp_socket)
    }
    
    /// Get the next socket shard in round-robin fashion
    pub fn get_shard(&self) -> &SocketShard {
        let index = self.current_shard.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.shards.len();
        &self.shards[index]
    }
    
    /// Get a specific shard by ID
    pub fn get_shard_by_id(&self, shard_id: usize) -> Option<&SocketShard> {
        self.shards.get(shard_id)
    }
    
    /// Get all shards
    pub fn get_all_shards(&self) -> &[SocketShard] {
        &self.shards
    }
    
    /// Get the number of shards
    pub fn num_shards(&self) -> usize {
        self.shards.len()
    }
}

/// Calculate optimal number of socket shards based on system resources
pub fn calculate_optimal_shards(concurrency: usize) -> usize {
    let cpu_count = num_cpus::get();
    
    // Use 1 shard per CPU core, but cap at reasonable limits
    let shards_by_cpu = cpu_count;
    
    // For very high concurrency, use more shards to distribute socket load
    let shards_by_concurrency = (concurrency / 10_000).max(1);
    
    // Take the maximum but cap at 16 shards to avoid excessive overhead
    std::cmp::min(16, std::cmp::max(shards_by_cpu, shards_by_concurrency))
}