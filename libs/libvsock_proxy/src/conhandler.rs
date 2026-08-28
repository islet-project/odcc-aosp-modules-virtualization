//! Connection handler module for vsock proxy
//!
//! This module provides functionality for handling incoming vsock connections
//! and proxying them to TCP servers.

use crate::conproto::{receive_connection_request, send_connection_response};
use crate::policy::{PolicyManager, Protocol};
use crate::stream_helpers::copy_bidirectional;
use clap::ValueEnum;
use log::{debug, error, info};
use std::fmt;
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::thread::JoinHandle;
use nix::poll::{poll, PollFd, PollFlags};
use std::os::unix::io::{AsRawFd, BorrowedFd};
use vsock::{VsockListener, VsockStream, VMADDR_CID_HOST, VMADDR_CID_LOCAL};

/// Vsock Context ID options for binding
///
/// The CID (Context ID) identifies the communication endpoint in the vsock namespace.
/// On the host, only three CID values are valid:
/// - CID=0: Wildcard - binds to all local contexts
/// - CID=1: Local loopback within the same context
/// - CID=2: The host's fixed identity (VMADDR_CID_HOST)
///
/// Guest VMs are assigned CIDs >= 3 by the hypervisor.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum VsockCid
{
    /// Wildcard - binds to all local contexts (CID=0)
    Any,
    /// Local loopback within the same context (CID=1)
    Local,
    /// The host's fixed identity in vsock namespace (CID=2)
    Host,
}

impl From<VsockCid> for u32
{
    fn from(cid: VsockCid) -> u32
    {
        match cid {
            VsockCid::Any => 0,
            VsockCid::Local => VMADDR_CID_LOCAL,
            VsockCid::Host => VMADDR_CID_HOST,
        }
    }
}

impl fmt::Display for VsockCid
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self {
            VsockCid::Any => write!(f, "any (CID=0)"),
            VsockCid::Local => write!(f, "local (CID=1)"),
            VsockCid::Host => write!(f, "host (CID=2)"),
        }
    }
}

/// Default proxy port
pub const DEFAULT_PORT: u32 = 1337;

/// Default server address
pub const DEFAULT_SERVER_ADDR: &str = "127.0.0.1:1337";

/// Default buffer size (64 KB)
pub const BUFFER_SIZE: usize = 65536;

/// Default TCP connection timeout in seconds
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// The timeout for read/write operations on TCP socket
pub const TCP_READ_WRITE_TIMEOUT: u64 = 60;

/// Configuration for the connection handler
pub struct ConnectionHandlerConfig
{
    /// The CID of the listening vsock
    pub vsock_cid: VsockCid,
    /// The port of the listening vsock
    pub vsock_port: u32,
    /// The server address (ip/name:port) of the TCP/IP server (used only if conproto is false)
    pub server_addr: Option<String>,
    /// Use connection protocol (if set, the server address is sent by ratls-get using connection protocol)
    pub conproto: bool,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// A policy manager instance controlling the white-list of TCP/IP servers
    pub policy_manager: Option<Arc<PolicyManager>>,
    /// The CID of VM. It is used to allow only one particular VM to connect to that proxy instance
    pub vm_cid: u32,
}

impl fmt::Debug for ConnectionHandlerConfig
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.debug_struct("ConnectionHandlerConfig")
            .field("vsock_cid", &self.vsock_cid)
            .field("vsock_port", &self.vsock_port)
            .field("server_addr", &self.server_addr)
            .field("conproto", &self.conproto)
            .field("timeout_secs", &self.timeout_secs)
            .field("policy_manager", &self.policy_manager.as_ref().map(|_| "..."))
            .field("vm_cid", &self.vm_cid)
            .finish()
    }
}

impl Default for ConnectionHandlerConfig
{
    fn default() -> Self
    {
        ConnectionHandlerConfig {
            vsock_cid: VsockCid::Host,
            vsock_port: DEFAULT_PORT,
            server_addr: Some(DEFAULT_SERVER_ADDR.to_string()),
            conproto: false,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            policy_manager: None,
            vm_cid: VMADDR_CID_LOCAL,
        }
    }
}

/// Connection listener responsible for handling vsock connections comming from a VM
pub struct ConnectionListener
{
    join_handle: JoinHandle<()>,
    stop_flag: Arc<AtomicBool>,
}

/// Connection handler for vsock proxy
pub struct ConnectionHandler
{
    config: ConnectionHandlerConfig,
    connection_listener: Option<ConnectionListener>,
}

impl fmt::Debug for ConnectionHandler
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.debug_struct("ConnectionHandler")
            .field("config", &self.config)
            .field("connection_listener", &self.connection_listener.as_ref().map(|_| "..."))
            .finish()
    }
}

impl ConnectionHandler
{
    /// Creates a new connection handler with the given configuration
    pub fn new(config: ConnectionHandlerConfig) -> Self
    {
        ConnectionHandler { config, connection_listener: None }
    }

    /// Starts the connection handler, listening for incoming vsock connections
    pub fn run(&mut self) -> io::Result<()>
    {
        info!(
            "Starting vsock proxy on {}:{}",
            u32::from(self.config.vsock_cid),
            self.config.vsock_port
        );

        if self.config.conproto {
            info!("Connection protocol is enabled.");
        }

        let listener = VsockListener::bind_with_cid_port(self.config.vsock_cid.into(), self.config.vsock_port)
                .map_err(|e| {
                    io::Error::new(e.kind(), format!("Failed to bind vsock: {}", e))
                })?;

        let listener = Arc::new(Mutex::new(listener));
        let listener_clone = Arc::clone(&listener);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = Arc::clone(&stop_flag);

        let conproto = self.config.conproto;
        let server_addr = self.config.server_addr.clone();
        let timeout_secs = self.config.timeout_secs;
        let policy_manager = self.config.policy_manager.clone();
        let vm_cid = self.config.vm_cid;

        let join_handle = std::thread::spawn(move || {
            loop {
                // Check stop flag before polling
                if stop_flag_clone.load(Ordering::Relaxed) {
                    info!("Stop flag set, exiting listener thread");
                    break;
                }

                // Poll with 100ms timeout - efficient waiting without busy-loop
                {
                    let listener_guard = listener_clone.lock().unwrap();
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
                                Ok((mut vsock, _addr)) => {
                                    let peer_addr = match vsock.peer_addr()
                                    {
                                        Ok(addr) => addr,
                                        Err(e) =>
                                        {
                                            error!("Failed to get peer address: {}", e);
                                            continue;
                                        }
                                    };

                                    info!(
                                        "New vsock connection from CID:{} port:{}",
                                        peer_addr.cid(),
                                        peer_addr.port()
                                    );

                                    if peer_addr.cid() != vm_cid {
                                        error!("Peer CID {} is not allowed to connect to the proxy", peer_addr.cid());
                                        continue;
                                    }

                                    let server_addr = if conproto
                                    {
                                        match receive_connection_request(&mut vsock)
                                        {
                                            Ok(request) => request.server_addr,
                                            Err(e) =>
                                            {
                                                error!("Failed to read connection request: {}", e);
                                                continue;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        match server_addr {
                                            Some(ref server_addr) => server_addr.clone(),
                                            None => {
                                                error!("Missing server address!");
                                                break;
                                            }
                                        }
                                    };

                                    // This is intentional. We don't handle connection in a thread because
                                    // we want handle them synchronously i.e. one connection at a time.
                                    if let Err(e) = handle_vsock_connection(
                                        vsock,
                                        &server_addr,
                                        timeout_secs,
                                        conproto,
                                        &policy_manager,
                                    )
                                    {
                                        error!("Connection handler error: {}", e);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to accept vsock connection: {}", e);
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Poll error: {}", e);
                            break;
                        }
                    }
                } // listener_guard dropped here
            }
        });

        self.connection_listener = Some(ConnectionListener { join_handle, stop_flag });

        Ok(())
    }

    /// Stops the connection listener thread
    pub fn stop(&mut self) -> io::Result<()> {
        if let Some(connection_listener) = self.connection_listener.take() {
            // Set the stop flag to signal the thread to exit
            connection_listener.stop_flag.store(true, Ordering::Relaxed);

            // Wait for the thread to finish
            connection_listener.join_handle.join().map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Thread join failed: {:?}", e))
            })?;
        }

        Ok(())
    }

    /// Join on the listener thread
    pub fn join(&mut self) -> io::Result<()> {
        if let Some(connection_listener) = self.connection_listener.take() {
            // Wait for the thread to finish
            connection_listener.join_handle.join().map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Thread join failed: {:?}", e))
            })?;
        }

        Ok(())
    }

}

/// Handles a single vsock connection by proxying it to a TCP server
fn handle_vsock_connection(
    mut vsock: VsockStream,
    tcp_addr: &str,
    timeout_secs: u64,
    conproto: bool,
    policy_manager: &Option<Arc<PolicyManager>>,
) -> io::Result<()>
{
    let (host_for_policy, port_for_policy) = tcp_addr
        .rsplit_once(':')
        .map(|(host, port)|
        {
            (
                host.trim_start_matches('[').trim_end_matches(']'),
                port.parse::<u16>(),
            )
        })
        .and_then(|(host, port_result)| port_result.ok().map(|port| (host, port)))
        .ok_or_else(|| {
            error!(
                "Invalid server address format '{}': expected host:port",
                tcp_addr
            );
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid address format, expected host:port",
            )
        })?;

    // Check if connection is allowed by policy
    if let Some(manager) = policy_manager
    {
        if !manager.is_allowed(host_for_policy, port_for_policy, Protocol::Tcp)
        {
            error!(
                "Connection to {}:{} is not allowed by policy",
                host_for_policy, port_for_policy
            );
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "Connection to {}:{} is not allowed by policy",
                    host_for_policy, port_for_policy
                ),
            ));
        }
    }

    // Resolve the address and try to connect to each resolved address (fallback support)
    let (tcp, connected_addr) = tcp_addr
        .to_socket_addrs()
        .map_err(|e| {
            error!("Failed to resolve server address '{}': {}", tcp_addr, e);
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Failed to resolve address: {}", e),
            )
        })?
        .find_map(|addr| {
            debug!("Attempting TCP connection to {}", addr);
            TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs))
                .map_err(|e| {
                    error!("Failed to connect to {}: {}", addr, e);
                    e
                })
                .ok()
                .map(|tcp| (tcp, addr))
        })
        .ok_or_else(|| {
            error!(
                "Failed to connect to any resolved address for '{}'",
                tcp_addr
            );
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Failed to connect to any resolved address",
            )
        })?;

    tcp.set_read_timeout(Some(Duration::from_secs(TCP_READ_WRITE_TIMEOUT)))
        .map_err(|e| {
            io::Error::new(e.kind(), format!("Failed to set TCP read timeout: {}", e))
        })?;
    tcp.set_write_timeout(Some(Duration::from_secs(TCP_READ_WRITE_TIMEOUT)))
        .map_err(|e| {
            io::Error::new(e.kind(), format!("Failed to set TCP write timeout: {}", e))
        })?;

    info!(
        "TCP connection established to {} (resolved from '{}'), starting proxy",
        connected_addr, tcp_addr
    );

    if conproto
    {
        send_connection_response(
            &mut vsock,
            true,
            &format!("Connection established to {}", connected_addr),
        )?;
    }

    // Pass policy manager and server info to copy_bidirectional for per-server byte tracking
    // Clone Arc and convert &str to String for thread-safe ownership
    let policy_manager_clone = policy_manager.clone();
    if let Err(e) = copy_bidirectional(
        vsock,
        tcp,
        policy_manager_clone,
        host_for_policy.to_string(),
        port_for_policy,
    )
    {
        error!("Copy bidirectional error: {}", e);
    }

    Ok(())
}
