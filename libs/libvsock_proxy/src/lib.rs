//! Library for vsock proxy

pub mod conhandler;
pub mod conproto;
pub mod policy;
pub mod stream_helpers;
pub mod datagram_handler;

// Re-export commonly used types at the crate root
pub use conhandler::{ConnectionHandler, ConnectionHandlerConfig, VsockCid, DEFAULT_PORT, BUFFER_SIZE, DEFAULT_TIMEOUT_SECS, TCP_READ_WRITE_TIMEOUT};
pub use conproto::{receive_connection_request, send_connection_response, ProxyRequest, ProxyResponse};
pub use policy::{PolicyManager, ServerRule, ServerWhitelist};
pub use stream_helpers::copy_bidirectional;
pub use datagram_handler::{
    DatagramHandler, DatagramHandlerConfig, DatagramHeader, HostnameCache,
    DATAGRAM_BUFFER_SIZE, MAX_HOSTNAME_LEN, POLL_TIMEOUT_MS,
};
