//! stellar-peerinfo - Get peer information from the Stellar overlay network.
//!
//! This CLI tool connects to a Stellar Core node, discovers peers,
//! and collects peer information from each discovered peer.

mod network;

use anyhow::{Context, Result};
use clap::Parser;
use network::Network;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use stellar_overlay::connect;
use stellar_xdr::curr::{NodeId, PeerAddress, PeerAddressIp, PublicKey, StellarMessage};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::prelude::*;

/// Get peer information from the Stellar overlay network.
///
/// Connects to a Stellar Core node, discovers known peers,
/// and collects information about each peer.
#[derive(Parser, Debug)]
#[command(name = "stellar-peerinfo", version, about)]
struct Args {
    /// Peer address to connect to (host:port)
    #[arg(short, long)]
    peer: Option<String>,

    /// Network passphrase (or "testnet" / "mainnet")
    #[arg(short, long, default_value = "testnet")]
    network: String,

    /// Timeout in seconds for waiting for responses
    #[arg(short, long, default_value = "10")]
    timeout: u64,

    /// Maximum number of concurrent peer connections
    #[arg(short = 'j', long, default_value = "10")]
    concurrency: usize,
}

/// JSON output for peer info.
#[derive(Serialize)]
struct PeerOutput {
    #[serde(rename = "type")]
    output_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    overlay_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ledger_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Set up tracing subscriber for stderr
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_level(true)
                .with_writer(std::io::stderr)
                .with_filter(LevelFilter::INFO),
        )
        .init();

    let args = Args::parse();

    // Resolve network
    let network = Network::from_str(&args.network);
    let peer = args.peer.as_deref().unwrap_or(network.default_peer());

    eprintln!("Connecting to {}", peer);
    let stream = TcpStream::connect(peer)
        .await
        .context("Failed to connect to peer")?;

    let net_id = network.id();
    let mut session = connect(stream, net_id.clone()).await?;
    eprintln!(
        "Connected to peer: {}",
        format_node_id(&session.peer_info().node_id)
    );

    // Wait for Peers message from peer (sent automatically after handshake)
    eprintln!("Waiting for peer list...");
    let response_timeout = Duration::from_secs(args.timeout);
    let peers = loop {
        match timeout(response_timeout, session.recv()).await {
            Ok(Ok(StellarMessage::Peers(peers))) => {
                eprintln!("Discovered {} peers", peers.len());
                break peers;
            }
            Ok(Ok(msg)) => {
                // Ignore other messages
                eprintln!("Received: {}", msg.name());
            }
            Ok(Err(e)) => {
                anyhow::bail!("Connection closed: {}", e);
            }
            Err(_) => {
                anyhow::bail!("Timeout waiting for peers message");
            }
        }
    };

    // Process all peers concurrently with semaphore to limit concurrency
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let net_id = Arc::new(net_id);

    let mut handles = Vec::new();

    for peer_addr in peers.iter() {
        let addr_str = format_peer_address(peer_addr);
        let sem = semaphore.clone();
        let net_id = net_id.clone();
        let timeout_duration = response_timeout;

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            eprintln!("Connecting to {}...", addr_str);

            let output = match get_peer_info(&addr_str, &net_id, timeout_duration).await {
                Ok(output) => output,
                Err(e) => PeerOutput {
                    output_type: "error".to_string(),
                    peer_id: None,
                    peer_address: Some(addr_str),
                    version: None,
                    overlay_version: None,
                    ledger_version: None,
                    error: Some(e.to_string()),
                },
            };

            // Print immediately as each completes
            println!("{}", serde_json::to_string(&output).unwrap());
        });

        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

/// Get basic peer info by connecting and performing handshake.
async fn get_peer_info(
    addr: &str,
    network_id: &stellar_xdr::curr::Hash,
    timeout_duration: Duration,
) -> Result<PeerOutput> {
    // Connect with timeout
    let stream = match timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => anyhow::bail!("Connection timeout"),
    };

    let session = connect(stream, network_id.clone()).await?;
    let info = session.peer_info();

    Ok(PeerOutput {
        output_type: "info".to_string(),
        peer_id: Some(format_node_id(&info.node_id)),
        peer_address: Some(addr.to_string()),
        version: Some(info.version_str.clone()),
        overlay_version: Some(info.overlay_version),
        ledger_version: Some(info.ledger_version),
        error: None,
    })
}

/// Format a NodeId for display.
fn format_node_id(node_id: &NodeId) -> String {
    match &node_id.0 {
        PublicKey::PublicKeyTypeEd25519(key) => hex::encode(&key.0),
    }
}

/// Format a PeerAddress for display.
fn format_peer_address(peer: &PeerAddress) -> String {
    let ip: IpAddr = match &peer.ip {
        PeerAddressIp::IPv4(ip) => IpAddr::V4(Ipv4Addr::from(*ip)),
        PeerAddressIp::IPv6(ip) => IpAddr::V6(Ipv6Addr::from(*ip)),
    };
    let addr = SocketAddr::new(ip, peer.port as u16);
    addr.to_string()
}
