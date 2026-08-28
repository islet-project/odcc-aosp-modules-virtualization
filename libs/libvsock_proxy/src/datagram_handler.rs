//! Datagram handler module for vsock proxy
//!
//! This module provides functionality for handling incoming vsock stream connections
//! and proxying them to UDP sockets with hostname resolution.
//!
//! Since SOCK_DGRAM is not supported for virtio and loopback vsock transports,
//! this implementation uses a stream-based vsock socket (VsockListener) with
//! a custom framing protocol over the stream.
//!
//! Frame format for vsock stream:
//! - hostname_len (1 byte): length of hostname string
//! - hostname (variable): hostname bytes
//! - port (2 bytes, big-endian): destination port
//! - payload_len (4 bytes, big-endian): length of payload data
//! - payload (variable): payload data

use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket, IpAddr, ToSocketAddrs};
use std::sync::{Arc, RwLock, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::Duration;
use std::thread::JoinHandle;
use vsock::{VsockListener, VsockStream, VMADDR_CID_LOCAL};
use crate::conhandler::VsockCid;
use crate::policy::{PolicyManager, Protocol};

/// Default buffer size for datagram packets (64 KB)
pub const DATAGRAM_BUFFER_SIZE: usize = 65536;

/// Maximum size for hostname in packet header
pub const MAX_HOSTNAME_LEN: usize = 255;

/// Timeout for polling vsock and UDP sockets (in milliseconds)
pub const POLL_TIMEOUT_MS: u16 = 1000;

/// Timeout for accepting new vsock connections (in milliseconds)
pub const ACCEPT_TIMEOUT_MS: u64 = 100;

/// Cache entry for IP <-> hostname mapping
#[derive(Debug, Clone)]
pub struct HostnameCacheEntry {
    /// The hostname
    pub hostname: String,
    /// The UDP port
    pub port: u16,
    /// The timestamp of last usage
    pub last_used: std::time::Instant,
}

/// Cache for IP <-> hostname mappings
#[derive(Debug)]
pub struct HostnameCache {
    /// Maps IP addresses to hostname entries
    ip_to_hostname: RwLock<HashMap<IpAddr, HostnameCacheEntry>>,
    /// Maps hostname:port to IP addresses (for reverse lookup)
    hostname_to_ip: RwLock<HashMap<(String, u16), IpAddr>>,
    /// Cache entry timeout
    cache_timeout: Duration,
}

impl HostnameCache {
    /// Creates a new hostname cache with the specified timeout
    pub fn new(cache_timeout: Duration) -> Self {
        HostnameCache {
            ip_to_hostname: RwLock::new(HashMap::new()),
            hostname_to_ip: RwLock::new(HashMap::new()),
            cache_timeout,
        }
    }

    /// Creates a new hostname cache with default timeout (5 minutes)
    pub fn with_default_timeout() -> Self {
        Self::new(Duration::from_secs(300))
    }

    /// Adds or updates a mapping in the cache
    pub fn insert(&self, ip: IpAddr, hostname: String, port: u16) {
        let entry = HostnameCacheEntry {
            hostname: hostname.clone(),
            port,
            last_used: std::time::Instant::now(),
        };

        // Remove old entry if IP was previously mapped to different hostname
        if let Ok(mut ip_map) = self.ip_to_hostname.write() {
            if let Some(old_entry) = ip_map.get(&ip) {
                if old_entry.hostname != hostname || old_entry.port != port {
                    let old_key = (old_entry.hostname.clone(), old_entry.port);
                    self.hostname_to_ip.write().unwrap().remove(&old_key);
                }
            }
            ip_map.insert(ip, entry);
        }

        // Update hostname -> IP mapping
        if let Ok(mut hostname_map) = self.hostname_to_ip.write() {
            hostname_map.insert((hostname, port), ip);
        }
    }

    /// Gets hostname for a given IP address
    pub fn get_hostname(&self, ip: &IpAddr, _port: u16) -> Option<(String, u16)> {
        // Clean up expired entries first
        self.cleanup_expired();

        // First, try to get the entry (just reading)
        let entry_opt = if let Ok(ip_map) = self.ip_to_hostname.read() {
            ip_map.get(ip).map(|e| (e.hostname.clone(), e.port))
        } else {
            None
        };

        // If we found an entry, update its last_used time
        if entry_opt.is_some() {
            if let Ok(mut ip_map_write) = self.ip_to_hostname.write() {
                if let Some(entry) = ip_map_write.get_mut(ip) {
                    entry.last_used = std::time::Instant::now();
                }
            }
        }

        entry_opt
    }

    /// Gets IP address for a given hostname and port
    pub fn get_ip(&self, hostname: &str, port: u16) -> Option<IpAddr> {
        // Clean up expired entries first
        self.cleanup_expired();

        if let Ok(hostname_map) = self.hostname_to_ip.read() {
            hostname_map.get(&(hostname.to_string(), port)).copied()
        } else {
            None
        }
    }

    /// Removes expired cache entries
    fn cleanup_expired(&self) {
        let now = std::time::Instant::now();

        if let Ok(mut ip_map) = self.ip_to_hostname.write() {
            let expired: Vec<IpAddr> = ip_map
                .iter()
                .filter(|(_, entry)| now.duration_since(entry.last_used) > self.cache_timeout)
                .map(|(ip, _)| *ip)
                .collect();

            for ip in &expired {
                if let Some(entry) = ip_map.remove(ip) {
                    self.hostname_to_ip.write().unwrap().remove(&(entry.hostname, entry.port));
                }
            }
        }
    }
}

impl Default for HostnameCache {
    fn default() -> Self {
        Self::with_default_timeout()
    }
}

/// Packet header format for vsock stream proxy
/// Layout:
/// - hostname_len (1 byte): length of hostname string
/// - hostname (variable): hostname bytes
/// - port (2 bytes, big-endian): destination port
/// - payload_len (4 bytes, big-endian): length of payload data
/// - payload (variable): payload data
#[derive(Debug, Clone)]
pub struct DatagramHeader {
    /// The hostname
    pub hostname: String,
    /// The UDP port
    pub port: u16,
    /// The payload length
    pub payload_len: u32,
}

impl DatagramHeader {
    /// Size of the fixed part of header (hostname_len + port + payload_len)
    const FIXED_SIZE: usize = 1 + 2 + 4;

    /// Calculates the total frame size from the header
    pub fn frame_size(&self) -> usize {
        Self::FIXED_SIZE + self.hostname.len() + self.payload_len as usize
    }

    /// Serializes the header to bytes (without payload)
    pub fn to_bytes(&self) -> Vec<u8> {
        let hostname_bytes = self.hostname.as_bytes();
        let hostname_len = hostname_bytes.len().min(MAX_HOSTNAME_LEN) as u8;

        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + hostname_len as usize);
        buf.push(hostname_len);
        buf.extend_from_slice(&hostname_bytes[..hostname_len as usize]);
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf.extend_from_slice(&self.payload_len.to_be_bytes());
        buf
    }

    /// Deserializes the header from bytes
    /// Returns (header, header_size) where header_size includes hostname_len + hostname + port + payload_len
    pub fn from_bytes(data: &[u8]) -> io::Result<(Self, usize)> {
        if data.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Empty packet",
            ));
        }

        let hostname_len = data[0] as usize;
        if hostname_len > MAX_HOSTNAME_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Hostname too long: {}", hostname_len),
            ));
        }

        let header_size = Self::FIXED_SIZE + hostname_len;
        if data.len() < header_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Header too short: expected at least {} bytes, got {}", header_size, data.len()),
            ));
        }

        let hostname = String::from_utf8(data[1..1 + hostname_len].to_vec())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid hostname UTF-8: {}", e),
                )
            })?;

        let port_start = 1 + hostname_len;
        let port = u16::from_be_bytes([data[port_start], data[port_start + 1]]);

        let payload_len_start = port_start + 2;
        let payload_len = u32::from_be_bytes([
            data[payload_len_start],
            data[payload_len_start + 1],
            data[payload_len_start + 2],
            data[payload_len_start + 3],
        ]);

        Ok((DatagramHeader { hostname, port, payload_len }, header_size))
    }

    /// Reads a complete frame from a stream
    /// Returns (header, payload)
    pub fn read_from_stream<R: Read>(reader: &mut R) -> io::Result<(Self, Vec<u8>)> {
        // Read hostname_len (1 byte)
        let mut hostname_len_buf = [0u8; 1];
        reader.read_exact(&mut hostname_len_buf)?;
        let hostname_len = hostname_len_buf[0] as usize;

        if hostname_len > MAX_HOSTNAME_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Hostname too long: {}", hostname_len),
            ));
        }

        // Read hostname
        let mut hostname_buf = vec![0u8; hostname_len];
        reader.read_exact(&mut hostname_buf)?;
        let hostname = String::from_utf8(hostname_buf)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid hostname UTF-8: {}", e),
                )
            })?;

        // Read port (2 bytes, big-endian)
        let mut port_buf = [0u8; 2];
        reader.read_exact(&mut port_buf)?;
        let port = u16::from_be_bytes(port_buf);

        // Read payload_len (4 bytes, big-endian)
        let mut payload_len_buf = [0u8; 4];
        reader.read_exact(&mut payload_len_buf)?;
        let payload_len = u32::from_be_bytes(payload_len_buf) as usize;

        // Read payload
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload)?;

        Ok((
            DatagramHeader {
                hostname,
                port,
                payload_len: payload_len as u32,
            },
            payload,
        ))
    }

    /// Writes a frame (header + payload) to a stream
    pub fn write_to_stream<W: Write>(&self, writer: &mut W, payload: &[u8]) -> io::Result<()> {
        let header_bytes = self.to_bytes();
        writer.write_all(&header_bytes)?;
        writer.write_all(payload)?;
        writer.flush()?;
        Ok(())
    }
}

/// Configuration for the datagram handler
#[derive(Clone)]
pub struct DatagramHandlerConfig {
    /// The CID of the vsock listening socket
    pub vsock_cid: VsockCid,
    /// The port of the vsock listening socket
    pub vsock_port: u32,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Cache timeout for hostname mappings
    pub cache_timeout_secs: u64,
    /// A policy manager instance controlling the white-list of UDP servers
    pub policy_manager: Option<Arc<PolicyManager>>,
    /// The CID of VM. It is used to allow only one particular VM to connect to that proxy instance
    pub vm_cid: u32,
}

impl std::fmt::Debug for DatagramHandlerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramHandlerConfig")
            .field("vsock_cid", &self.vsock_cid)
            .field("vsock_port", &self.vsock_port)
            .field("timeout_secs", &self.timeout_secs)
            .field("cache_timeout_secs", &self.cache_timeout_secs)
            .field("vm_cid", &self.vm_cid)
            .field("policy_manager", &self.policy_manager.as_ref().map(|_| "..."))
            .finish()
    }
}

impl Default for DatagramHandlerConfig {
    fn default() -> Self {
        DatagramHandlerConfig {
            vsock_cid: VsockCid::Host,
            vsock_port: 1338, // Default datagram port (different from stream port 1337)
            timeout_secs: 60,
            cache_timeout_secs: 300,
            vm_cid: VMADDR_CID_LOCAL,
            policy_manager: None,
        }
    }
}

/// Datagram handler for vsock proxy
///
/// This handler uses VsockListener (SOCK_STREAM) with a custom framing protocol.
/// - Vsock listener socket bound to configured CID:port
/// - UDP socket bound to 0.0.0.0:0 (ephemeral port)
/// - Each vsock stream frame contains: header (hostname_len + hostname + port + payload_len) + payload
/// - UDP socket sends/receives datagrams to resolved IP:port
/// - Response includes header with hostname from cache
pub struct DatagramHandler {
    config: DatagramHandlerConfig,
    hostname_cache: Arc<HostnameCache>,
    udp_socket: Option<Arc<UdpSocket>>,
    vsock_listener: Option<Arc<Mutex<VsockListener>>>,
    datagram_listener: Option<DatagramListener>,
    policy_manager: Option<Arc<PolicyManager>>,
}

impl fmt::Debug for DatagramHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramHandler")
            .field("config", &self.config)
            .field("hostname_cache", &self.hostname_cache)
            .finish()
    }
}

use std::os::unix::io::{AsRawFd, BorrowedFd};
use nix::poll::{poll, PollFd, PollFlags};

/// Datagram listener wrapper that holds the thread handle and stop flag
struct DatagramListener {
    join_handle: JoinHandle<()>,
    stop_flag: Arc<AtomicBool>,
}

impl DatagramHandler {
    /// Creates a new datagram handler with the given configuration
    pub fn new(config: DatagramHandlerConfig) -> Self {
        let cache_timeout = Duration::from_secs(config.cache_timeout_secs);
        DatagramHandler {
            config,
            hostname_cache: Arc::new(HostnameCache::new(cache_timeout)),
            udp_socket: None,
            vsock_listener: None,
            datagram_listener: None,
            policy_manager: None,
        }
    }

    /// Starts the datagram handler
    /// - Creates UDP socket bound to 0.0.0.0:0 (ephemeral port)
    /// - Creates VsockListener bound to configured CID:port
    /// - Starts accepting connections and forwarding loop
    pub fn run(&mut self) -> io::Result<()> {
        info!(
            "Starting vsock datagram proxy on CID:{} port:{}",
            self.config.vsock_cid,
            self.config.vsock_port
        );

        // Create UDP socket bound to 0.0.0.0:0 (ephemeral port)
        let udp_socket = UdpSocket::bind("0.0.0.0:0")?;
        udp_socket.set_read_timeout(Some(Duration::from_secs(self.config.timeout_secs)))?;
        udp_socket.set_write_timeout(Some(Duration::from_secs(self.config.timeout_secs)))?;

        let udp_addr = udp_socket.local_addr()?;
        info!("UDP socket bound to {}", udp_addr);

        let udp_socket = Arc::new(udp_socket);

        // Create vsock listener socket (SOCK_STREAM)
        let vsock_listener = VsockListener::bind_with_cid_port(
            self.config.vsock_cid as u32,
            self.config.vsock_port,
        )
        .map_err(|e| {
            io::Error::new(e.kind(), format!("Failed to bind vsock listener socket: {}", e))
        })?;

        info!("Vsock listener socket bound to CID:{} port:{}",
              self.config.vsock_cid, self.config.vsock_port);

        let vsock_listener = Arc::new(Mutex::new(vsock_listener));

        self.udp_socket = Some(Arc::clone(&udp_socket));
        self.vsock_listener = Some(Arc::clone(&vsock_listener));

        // Start the connection accept loop
        let hostname_cache = Arc::clone(&self.hostname_cache);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = Arc::clone(&stop_flag);
        let vm_cid = self.config.vm_cid;
        let policy_manager = self.config.policy_manager.clone();
        self.policy_manager = policy_manager.clone();

        let join_handle = std::thread::spawn(move || {
            if let Err(e) = connection_accept_loop(
                vsock_listener,
                udp_socket,
                hostname_cache,
                stop_flag_clone,
                vm_cid,
                policy_manager,
            ) {
                error!("Connection accept loop error: {}", e);
            }
        });

        self.datagram_listener = Some(DatagramListener { join_handle, stop_flag });

        Ok(())
    }

    /// Stops the datagram listener thread
    pub fn stop(&mut self) -> io::Result<()> {
        if let Some(datagram_listener) = self.datagram_listener.take() {
            // Set the stop flag to signal the thread to exit
            datagram_listener.stop_flag.store(true, Ordering::Relaxed);

            // Wait for the thread to finish
            datagram_listener.join_handle.join().map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Thread join failed: {:?}", e))
            })?;
        }

        Ok(())
    }

    /// Join on the listener thread
    pub fn join(&mut self) -> io::Result<()> {
        if let Some(datagram_listener) = self.datagram_listener.take() {
            // Wait for the thread to finish
            datagram_listener.join_handle.join().map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Thread join failed: {:?}", e))
            })?;
        }

        Ok(())
    }

    /// Gets the hostname cache reference
    pub fn get_cache(&self) -> Arc<HostnameCache> {
        Arc::clone(&self.hostname_cache)
    }
}

/// Main connection accept loop
/// - Accepts incoming vsock stream connections
/// - Spawns a thread for each connection to handle datagram framing
/// - Uses polling with timeout to allow graceful shutdown via stop_flag
fn connection_accept_loop(
    vsock_listener: Arc<Mutex<VsockListener>>,
    udp_socket: Arc<UdpSocket>,
    hostname_cache: Arc<HostnameCache>,
    stop_flag: Arc<AtomicBool>,
    vm_cid: u32,
    policy_manager: Option<Arc<PolicyManager>>,
) -> io::Result<()> {
    loop {
        // Check stop flag before polling
        if stop_flag.load(Ordering::Relaxed) {
            info!("Stop flag set, exiting listener thread");
            break;
        }

        // Poll with 100ms timeout - efficient waiting without busy-loop
        {
            let listener_guard = vsock_listener.lock().unwrap();
            // Use raw fd + BorrowedFd for AOSP nix crate compatibility
            let raw_fd = listener_guard.as_raw_fd();
            // Safety: BorrowedFd is only used within this scope while listener_guard is alive
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
            let poll_fd = PollFd::new(borrowed_fd, PollFlags::POLLIN);

            // nix 0.28 uses PollTimeout type - u16 for milliseconds
            match poll(&mut [poll_fd], 100u16) {
                Ok(0) => {
                    // Timeout - no connection ready, drop guard and continue
                    drop(listener_guard);
                    continue;
                }
                Ok(_) => {
                    // Connection ready, accept it (still holding the lock)
                    match listener_guard.accept() {
                        Ok((stream, peer_addr)) => {
                            info!("Accepted vsock connection from CID:{} port:{}",
                                  peer_addr.cid(), peer_addr.port());

                            if peer_addr.cid() != vm_cid {
                                error!("Peer CID {} is not allowed to connect to the proxy", peer_addr.cid());
                                continue;
                            }

                            // Spawn a thread to handle this connection
                            let stream_hostname_cache = Arc::clone(&hostname_cache);
                            let stream_udp_socket = Arc::clone(&udp_socket);
                            let stream_policy_manager = policy_manager.clone();

                            // This is intentional. We don't handle connection in a thread because
                            // we want handle them synchronously i.e. one connection at a time.
                            if let Err(e) = handle_vsock_datagrams_over_stream(
                                stream,
                                stream_udp_socket,
                                stream_hostname_cache,
                                stream_policy_manager,
                            ) {
                                warn!("Vsock stream handling error: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to accept vsock connection: {}", e);
                            // Continue accepting other connections
                        }
                    }
                }
                Err(e) => {
                    warn!("Poll error: {}", e);
                    // Continue accepting other connections
                }
            }
        } // listener_guard dropped here
    }

    Ok(())
}

/// Handles a single vsock stream to
/// exchange datagrams over UDP socket
/// - Reads framed packet from vsock stream (header + payload)
/// - Resolves hostname to IP and sends the payload to UDP endpoint
/// - Receives UDP response
/// - Sends framed packet over vsock stream
fn handle_vsock_datagrams_over_stream(
    mut stream: VsockStream,
    udp_socket: Arc<UdpSocket>,
    hostname_cache: Arc<HostnameCache>,
    policy_manager: Option<Arc<PolicyManager>>,
) -> io::Result<()> {
    // Set timeouts on the stream
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))?;

    loop {
        // Try to read a complete frame from the stream
        match DatagramHeader::read_from_stream(&mut stream) {
            Ok((header, payload)) => {
                debug!(
                    "Received vsock frame: hostname={}, port={}, payload_len={}",
                    header.hostname,
                    header.port,
                    payload.len()
                );

                // Check if connection is allowed by policy
                if let Some(manager) = &policy_manager {
                    if !manager.is_allowed(&header.hostname, header.port, Protocol::Udp) {
                        error!(
                            "UDP connection to {}:{} is not allowed by policy",
                            header.hostname, header.port
                        );
                        continue; // Skip this packet, but keep connection open for other packets
                    }
                }

                // Resolve hostname to IP
                let dest_addr = if let Some(ip) = hostname_cache.get_ip(&header.hostname, header.port) {
                    debug!("Cache hit for {}:{} -> {}", header.hostname, header.port, ip);
                    SocketAddr::new(ip, header.port)
                } else {
                    // Resolve hostname
                    let resolved = format!("{}:{}", header.hostname, header.port)
                        .to_socket_addrs()
                        .map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!("Failed to resolve {}: {}", header.hostname, e),
                            )
                        })?
                        .next()
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!("No addresses found for {}", header.hostname),
                            )
                        })?;

                    // Cache the resolution
                    hostname_cache.insert(resolved.ip(), header.hostname.clone(), header.port);
                    debug!("Resolved and cached {}:{} -> {}", header.hostname, header.port, resolved.ip());

                    resolved
                };

                // Check and add TX bytes if policy manager is present
                if let Some(manager) = &policy_manager {
                    if let Err(e) = manager.check_and_add_tx_bytes(
                        &header.hostname,
                        header.port,
                        Protocol::Udp,
                        payload.len() as u64,
                    ) {
                        error!("TX bytes limit exceeded for UDP {}:{}: {}", header.hostname, header.port, e);
                        continue; // Skip this packet due to limit
                    }
                }

                // Send to UDP destination
                udp_socket.send_to(&payload, dest_addr)?;
                debug!("Sent {} bytes to UDP {}", payload.len(), dest_addr);

                // Wait for UDP response with timeout
                udp_socket.set_read_timeout(Some(Duration::from_millis(1000)))?;

                let mut response_buf = [0u8; DATAGRAM_BUFFER_SIZE];
                match udp_socket.recv_from(&mut response_buf) {
                    Ok((response_len, src_udp_addr)) => {
                        debug!("Received {} bytes response from UDP {}", response_len, src_udp_addr);

                        if src_udp_addr != dest_addr {
                            warn!("Received UDP packet from {} which is not an expected responder {}", src_udp_addr, dest_addr);
                            break;
                        }

                        // Look up hostname for source IP
                        let (response_hostname, response_port) = if let Some((hostname, port)) = hostname_cache.get_hostname(&src_udp_addr.ip(), src_udp_addr.port()) {
                            debug!("Cache hit for {} -> {}:{}", src_udp_addr.ip(), hostname, port);
                            (hostname, port)
                        } else {
                            // If not in cache, just break the loop
                            warn!("Cache miss while receiving UDP response for {}", src_udp_addr.ip());
                            break;
                        };

                        // Create response header
                        let response_header = DatagramHeader {
                            hostname: response_hostname,
                            port: response_port,
                            payload_len: response_len as u32,
                        };

                        // Send response back through vsock stream with framing
                        if let Err(e) = response_header.write_to_stream(&mut stream, &response_buf[..response_len]) {
                            warn!("Failed to send response to vsock stream: {}", e);
                            break;
                        }
                        debug!("Sent {} bytes response to vsock stream", response_len);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                        debug!("No UDP response received within timeout");
                    }
                    Err(e) => {
                        warn!("Error receiving UDP response: {}", e);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // Client closed the connection
                debug!("Vsock stream closed by peer");
                break;
            }
            Err(e) => {
                warn!("Failed to read frame from vsock stream: {}", e);
                break;
            }
        }
    }

    // Print diagnostic information after finishing
    if let Some(manager) = &policy_manager {
        manager.log_connection_complete("UDP", 0, Protocol::Udp);
    }
    info!("Vsock datagram handler finished");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datagram_header_serialization() {
        let header = DatagramHeader {
            hostname: "example.com".to_string(),
            port: 443,
            payload_len: 100,
        };

        let bytes = header.to_bytes();
        // Header should be: 1 (hostname_len) + 11 (hostname) + 2 (port) + 4 (payload_len) = 18
        assert_eq!(bytes.len(), 18);

        let (parsed, size) = DatagramHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.hostname, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.payload_len, 100);
        assert_eq!(size, 18);
    }

    #[test]
    fn test_datagram_header_with_payload() {
        let payload = b"Hello, World!";
        let header = DatagramHeader {
            hostname: "test.local".to_string(),
            port: 8080,
            payload_len: payload.len() as u32,
        };

        let mut bytes = header.to_bytes();
        bytes.extend_from_slice(payload);

        // Parse header only
        let (parsed, header_size) = DatagramHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.hostname, "test.local");
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.payload_len, payload.len() as u32);
        assert_eq!(header_size, 1 + 10 + 2 + 4); // hostname_len + hostname + port + payload_len

        // Verify payload is intact
        assert_eq!(&bytes[header_size..], payload);
    }

    #[test]
    fn test_hostname_cache() {
        use std::net::Ipv4Addr;

        let cache = HostnameCache::new(Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        cache.insert(ip, "example.com".to_string(), 443);

        // Test IP -> hostname lookup
        let (hostname, port) = cache.get_hostname(&ip, 443).unwrap();
        assert_eq!(hostname, "example.com");
        assert_eq!(port, 443);

        // Test hostname -> IP lookup
        let resolved_ip = cache.get_ip("example.com", 443).unwrap();
        assert_eq!(resolved_ip, ip);
    }

    #[test]
    fn test_hostname_cache_expiry() {
        use std::net::Ipv4Addr;
        use std::thread;

        let cache = HostnameCache::new(Duration::from_millis(100));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        cache.insert(ip, "test.local".to_string(), 8080);

        // Should be found immediately
        assert!(cache.get_hostname(&ip, 8080).is_some());

        // Wait for expiry
        thread::sleep(Duration::from_millis(150));

        // Should be expired now
        assert!(cache.get_hostname(&ip, 8080).is_none());
    }
}
