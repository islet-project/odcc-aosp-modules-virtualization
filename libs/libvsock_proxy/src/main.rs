//! A command line tool for vsock proxy

use clap::{Parser, ValueEnum};
use log::{error, info};
use std::io;
use std::sync::Arc;
use vsock::VMADDR_CID_LOCAL;

use vsock_proxy::conhandler::{
    ConnectionHandler, ConnectionHandlerConfig, VsockCid
};
use vsock_proxy::datagram_handler::{
    DatagramHandler, DatagramHandlerConfig
};
use vsock_proxy::policy::PolicyManager;

/// Proxy mode: stream (TCP) or datagram (UDP)
#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProxyMode {
    /// Stream mode - proxies vsock stream to TCP sockets
    Stream,
    /// Datagram mode - proxies vsock datagrams to UDP sockets
    Datagram,
}

impl std::fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyMode::Stream => write!(f, "stream"),
            ProxyMode::Datagram => write!(f, "datagram"),
        }
    }
}

#[derive(Parser, Debug)]
struct Args
{
    /// Proxy mode: stream (TCP) or datagram (UDP)
    #[arg(long, default_value_t = ProxyMode::Stream)]
    mode: ProxyMode,

    /// The Context ID of vsock listening socket.
    #[arg(long, default_value_t = VsockCid::Host)]
    vsock_cid: VsockCid,

    /// The port of vsock listening socket
    #[arg(long, default_value_t = 1337)]
    vsock_port: u32,

    /// The IP address and port of remote server (address:port) - used only in stream mode
    #[arg(long, default_value = "127.0.0.1:1337")]
    server_addr: String,

    /// Use connection protocol to select the server (ratls-get should also run with that option)
    #[arg(short, long, default_value_t = false)]
    conproto: bool,

    /// Connection timeout in seconds
    #[arg(long, default_value_t = 60)]
    timeout_secs: u64,

    /// Cache timeout for hostname mappings in datagram mode (seconds)
    #[arg(long, default_value_t = 300)]
    cache_timeout_secs: u64,

    /// Turns on verbose logging
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Path to JSON policy file for server whitelist (stream mode only)
    #[arg(long)]
    policy_file: Option<String>,

    /// The CID of VM that is allowed to connect to the proxy (stream mode only)
    #[arg(long, default_value_t = VMADDR_CID_LOCAL)]
    vm_cid: u32,
}

fn main() -> io::Result<()>
{
    let args = Args::parse();

    if !args.verbose && std::env::var("RUST_LOG").is_ok() {
        env_logger::init_from_env(env_logger::Env::default());
    } else {
        let log_level = if args.verbose { "debug" } else { "info" };
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
            .init();
    }

    match args.mode {
        ProxyMode::Stream => run_stream_mode(&args),
        ProxyMode::Datagram => run_datagram_mode(&args),
    }
}

fn run_stream_mode(args: &Args) -> io::Result<()>
{
    info!("Running in stream mode (vsock stream -> TCP)");

    let policy_manager = create_policy_manager(&args.policy_file)?;

    let server_addr = if args.conproto {
        None
    } else {
        Some(args.server_addr.clone())
    };

    let config = ConnectionHandlerConfig {
        vsock_cid: args.vsock_cid,
        vsock_port: args.vsock_port,
        server_addr,
        conproto: args.conproto,
        timeout_secs: args.timeout_secs,
        policy_manager: policy_manager.clone(),
        vm_cid: args.vm_cid,
    };

    let mut handler = ConnectionHandler::new(config);
    if let Err(e) = handler.run() {
        error!("Stream proxy handler error: {}", e);
        return Err(e);
    }

    handler.join()?;

    Ok(())
}

fn run_datagram_mode(args: &Args) -> io::Result<()>
{
    info!("Running in datagram mode (vsock datagram -> UDP)");

    let policy_manager = create_policy_manager(&args.policy_file)?;

    let config = DatagramHandlerConfig {
        vsock_cid: args.vsock_cid,
        vsock_port: args.vsock_port,
        timeout_secs: args.timeout_secs,
        cache_timeout_secs: args.cache_timeout_secs,
        vm_cid: args.vm_cid,
        policy_manager,
    };

    let mut handler = DatagramHandler::new(config);
    if let Err(e) = handler.run() {
        error!("Datagram proxy handler error: {}", e);
        return Err(e);
    }

    handler.join()?;

    Ok(())
}

/// Creates a policy manager from the given policy file path
/// Returns None if no policy file is provided
fn create_policy_manager(policy_file: &Option<String>) -> io::Result<Option<Arc<PolicyManager>>> {
    if let Some(policy_file) = policy_file {
        let manager = PolicyManager::new();
        manager.load_from_file(policy_file).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to load policy file '{}': {}", policy_file, e),
            )
        })?;
        info!("Successfully loaded policy from '{}'", policy_file);
        manager.log_policy();
        Ok(Some(Arc::new(manager)))
    } else {
        Ok(None)
    }
}
