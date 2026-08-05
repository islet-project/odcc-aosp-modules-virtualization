//! A command line tool for vsock proxy

use clap::Parser;
use log::{error, info};
use std::io;
use std::sync::Arc;
use vsock::VMADDR_CID_LOCAL;

use vsock_proxy::conhandler::{
    ConnectionHandler, ConnectionHandlerConfig, VsockCid
};
use vsock_proxy::policy::PolicyManager;


#[derive(Parser, Debug)]
struct Args
{
    /// The Context ID of vsock listening socket.
    #[arg(long, default_value_t = VsockCid::Host)]
    vsock_cid: VsockCid,

    /// The port of vsock listening socket
    #[arg(long, default_value_t = 1337)]
    vsock_port: u32,

    /// The IP address and port of remote server (addr:port)
    #[arg(long, default_value = "127.0.0.1:1337")]
    server_addr: String,

    /// Use connection protocol to select the server (ratls-get should also run with that option)
    #[arg(short, long, default_value_t = false)]
    conproto: bool,

    /// TCP connection timeout in seconds
    #[arg(long, default_value_t = 60)]
    timeout_secs: u64,

    /// Turns on verbose logging
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Path to JSON policy file for server whitelist
    #[arg(long)]
    policy_file: Option<String>,

    /// The CID of VM that is allowed to connect to the proxy
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

    let policy_manager = if let Some(policy_file) = &args.policy_file {
        let manager = PolicyManager::new();
        manager.load_from_file(policy_file).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to load policy file '{}': {}", policy_file, e),
            )
        })?;
        info!("Successfully loaded policy from '{}'", policy_file);
        manager.log_policy();
        Some(Arc::new(manager))
    } else {
        None
    };

    let server_addr = if args.conproto {
        None
    } else {
        Some(args.server_addr)
    };

    let config = ConnectionHandlerConfig {
        vsock_cid: args.vsock_cid,
        vsock_port: args.vsock_port,
        server_addr,
        conproto: args.conproto,
        timeout_secs: args.timeout_secs,
        policy_manager,
        vm_cid: args.vm_cid,
    };

    let mut handler = ConnectionHandler::new(config);
    if let Err(e) = handler.run() {
        error!("Proxy handler error: {}", e);
        return Err(e);
    }

    handler.join()?;

    Ok(())
}
