//! Stellar overlay network protocol implementation.
//!
//! This crate provides functionality for connecting to and communicating
//! with Stellar Core nodes via the peer-to-peer overlay protocol.
//!
//! # Overview
//!
//! The Stellar network uses a peer-to-peer overlay protocol for nodes to
//! communicate. This crate implements the client side of that protocol,
//! allowing you to:
//!
//! - Connect to Stellar Core nodes
//! - Perform authenticated handshakes
//! - Send and receive protocol messages (transactions, SCP messages, etc.)
//!
//! # Example
//!
//! ```no_run
//! use stellar_overlay::{handshake, network_id, Log};
//! use stellar_xdr::curr::{StellarMessage, TransactionEnvelope};
//! use tokio::net::TcpStream;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to a Stellar Core node
//!     let stream = TcpStream::connect("core-testnet1.stellar.org:11625").await?;
//!
//!     // Compute network ID from passphrase
//!     let network = network_id("Test SDF Network ; September 2015");
//!
//!     // Perform authenticated handshake
//!     let mut session = handshake(stream, network, 11625, |log| {
//!         match log {
//!             Log::Sending(msg) => println!("-> {}", msg),
//!             Log::Received(msg) => println!("<- {}", msg),
//!             Log::Error(msg) => eprintln!("Error: {}", msg),
//!         }
//!     }).await?;
//!
//!     // Send a transaction
//!     // let tx: TransactionEnvelope = ...;
//!     // session.send_message(StellarMessage::Transaction(tx)).await?;
//!
//!     // Receive messages from the peer
//!     let msg = session.recv().await?;
//!     println!("Received: {:?}", msg);
//!
//!     Ok(())
//! }
//! ```
//!
//! # Network Passphrases
//!
//! Common network passphrases:
//!
//! - **Testnet**: `"Test SDF Network ; September 2015"`
//! - **Mainnet**: `"Public Global Stellar Network ; September 2015"`
//! - **Local/Standalone**: `"Standalone Network ; February 2017"`
//!
//! # Known Peers
//!
//! Some known peers useful for testing:
//!
//! - **Testnet**: `core-testnet1.stellar.org:11625`
//! - **Mainnet**: `core-live-a.stellar.org:11625`

mod crypto;
mod framing;
mod handshake;
mod session;

pub use crypto::network_id;
pub use handshake::{handshake, Error, Log};
pub use session::PeerSession;
