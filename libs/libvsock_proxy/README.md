# What is it?

This project provides a command line tool (built using AOSP's Soong or cargo tools) and a library (AOSP) that implements vsock proxy functionality.

Vsock proxy is a service that routes traffic between vsock and TCP/IP. It receives connections on a listening vsock socket, establishes connections to a TCP/IP server, and transfers TX/RX streams between vsock and TCP/IP sockets.

The proxy runs on the host and allows services running inside VMs that don't have access to a TCP/IP stack to communicate with the outside world. The main use case is to enable Android Confidential Services ([docs](https://islet-project.github.io/odcc-android-cc-docs/intro.html)) running inside Realm Linux to perform remote attestation and provisioning of confidential data over a TLS channel using the [ratls-get](https://github.com/islet-project/ratls/tree/main/tools/ratls-get) tool.

The proxy imposes additional restrictions on TCP/IP connections. Users can provide a server whitelist and a TX byte limit for data sent to the server.

## Building

As a stand-alone command line tool that can be run on an Ubuntu PC.

```
cargo build
```

As a stand-alone command line tool that can be run on Android.

```
# setup the AOSP build environment
m vsock_proxy_cmd
```

Note, that the `libvsock_proxy` is used by `virtmgr` (AVF component) to run one vsock service per one VM instance.

## Running

To run the proxy listening on localhost (CID=1) on port 1234 and establish a connection with a TCP/IP server at localhost:1337, run the following command:

```
vsock-proxy --vsock-cid local --vsock-port 1234 --server-addr localhost:1337 --verbose
```

To use the connection protocol (where the vsock client sends a TCP/IP server address and port), use the `--conproto` option. To enforce a whitelist and traffic policy, provide a policy file using the `--policy-file` option. Here is an example that uses both the connection protocol and a policy file:

NOTE: To use the **connection protocol**, the clients like `ratls-get` must also be invoked with the `--conproto` option.

```
vsock-proxy --vsock-cid local --vsock-port 1234 --server-addr localhost:1337 --verbose --policy-file whitelist-policy.json --conproto
```

The example policy file can be found in `whitelist-policy.json`. It contains a JSON array of objects with the following fields:

- `address` - the IPv4/IPv6 address or hostname of the server
- `port` - the port of the server
- `tx_bytes_limit` - the hard limit for the number of TX bytes that a particular server can receive

