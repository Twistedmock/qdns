use anyhow::Result;
use dashmap::DashSet;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::Duration;

/// A simple pool for creating UDP sockets with optimizations
pub struct UdpSocketPool {
    max_sockets: usize,
    socket_timeout: Duration,
    verbose: bool,
    created_sockets: Arc<DashSet<usize>>,
    next_id: std::sync::atomic::AtomicUsize,
}

impl UdpSocketPool {
    /// Create a new UDP socket pool
    pub fn new(max_sockets: usize, socket_timeout: Duration, verbose: bool) -> Self {
        Self {
            max_sockets,
            socket_timeout,
            verbose,
            created_sockets: Arc::new(DashSet::new()),
            next_id: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Get a socket (always creates new socket for simplicity and reliability)
    pub async fn get_socket(&self) -> Result<Arc<UdpSocket>> {
        // Create a new socket with optimized settings
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        
        // Configure socket for optimal performance
        self.configure_socket(&socket).await?;
        
        if self.verbose {
            let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.created_sockets.insert(id);
            eprintln!("🔌 Created UDP socket #{}, total active: {}", id, self.created_sockets.len());
        }

        Ok(Arc::new(socket))
    }

    /// Configure socket for optimal performance
    async fn configure_socket(&self, socket: &UdpSocket) -> Result<()> {
        // Set socket options for better performance on Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            
            unsafe {
                let fd = socket.as_raw_fd();
                
                // Set socket buffer sizes to reduce buffer exhaustion
                let send_buffer_size = 1024 * 1024; // 1MB
                let recv_buffer_size = 1024 * 1024; // 1MB
                
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &send_buffer_size as *const i32 as *const libc::c_void,
                    std::mem::size_of::<i32>() as libc::socklen_t,
                );
                
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &recv_buffer_size as *const i32 as *const libc::c_void,
                    std::mem::size_of::<i32>() as libc::socklen_t,
                );
                
                // Enable socket reuse
                let reuse = 1i32;
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &reuse as *const i32 as *const libc::c_void,
                    std::mem::size_of::<i32>() as libc::socklen_t,
                );
            }
        }
        
        Ok(())
    }

    /// Get pool statistics
    pub fn stats(&self) -> (usize, usize) {
        (self.created_sockets.len(), self.max_sockets)
    }
}