//! txsub - Submit transactions to the Stellar overlay network.
//!
//! This CLI tool connects to a Stellar Core node and submits transactions
//! directly via the peer-to-peer overlay protocol.
//!
//! Usage:
//!   echo "BASE64_ENCODED_TX" | txsub
//!
//! The tool reads a base64-encoded transaction envelope from stdin,
//! connects to the Stellar Testnet, performs the peer handshake,
//! and sends the transaction.

mod crypto;
mod framing;
mod handshake;
mod session;

use anyhow::{bail, Context, Result};
use std::io::{self, Read};
use std::time::Duration;
use stellar_xdr::curr::{ReadXdr, StellarMessage, TransactionEnvelope};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::crypto::{network_id, TESTNET_PASSPHRASE};
use crate::handshake::handshake;

/// Default peer to connect to (Stellar Testnet).
const DEFAULT_PEER: &str = "core-testnet1.stellar.org:11625";

/// Local listening port to advertise (not actually listening).
const LOCAL_LISTENING_PORT: i32 = 11625;

/// Timeout for waiting for responses after sending transaction.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<()> {
    // Read transaction from stdin
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("Failed to read from stdin")?;

    let input = input.trim();
    if input.is_empty() {
        bail!("No transaction provided on stdin");
    }

    // Decode base64
    let tx_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, input)
        .context("Failed to decode base64")?;

    // Parse as TransactionEnvelope
    let tx_envelope =
        TransactionEnvelope::from_xdr(&tx_bytes, stellar_xdr::curr::Limits::none())
            .context("Failed to parse transaction envelope")?;

    // Connect to peer
    eprintln!("Connecting to {}...", DEFAULT_PEER);
    let stream = TcpStream::connect(DEFAULT_PEER)
        .await
        .context("Failed to connect to peer")?;

    // Compute network ID
    let net_id = network_id(TESTNET_PASSPHRASE);

    // Perform handshake
    eprintln!("Performing handshake...");
    let mut session = handshake(stream, net_id, LOCAL_LISTENING_PORT).await?;

    eprintln!("Authenticated successfully");

    // Send transaction
    eprintln!("Sending transaction...");
    let tx_msg = StellarMessage::Transaction(tx_envelope);
    session.send_message(tx_msg).await?;

    eprintln!("Transaction sent, waiting for response...");

    // Wait for responses with timeout
    loop {
        match timeout(RESPONSE_TIMEOUT, session.recv()).await {
            Ok(Ok(msg)) => {
                print_message(&msg);
                // If we got an error, exit with failure
                if matches!(msg, StellarMessage::ErrorMsg(_)) {
                    std::process::exit(1);
                }
            }
            Ok(Err(e)) => {
                // Connection error or EOF
                eprintln!("Connection closed: {}", e);
                break;
            }
            Err(_) => {
                // Timeout - no more messages
                eprintln!("No further responses (timeout)");
                break;
            }
        }
    }

    Ok(())
}

/// Print a StellarMessage in human-readable format.
fn print_message(msg: &StellarMessage) {
    match msg {
        StellarMessage::ErrorMsg(e) => {
            eprintln!(
                "ERROR: {:?} - {}",
                e.code,
                String::from_utf8_lossy(&e.msg.to_vec())
            );
        }
        StellarMessage::Hello(h) => {
            eprintln!(
                "HELLO: version={}, overlay={}, peer={}",
                h.ledger_version,
                h.overlay_version,
                String::from_utf8_lossy(&h.version_str.to_vec())
            );
        }
        StellarMessage::Auth(a) => {
            eprintln!("AUTH: flags={}", a.flags);
        }
        StellarMessage::SendMore(s) => {
            eprintln!("SEND_MORE: num_messages={}", s.num_messages);
        }
        StellarMessage::SendMoreExtended(s) => {
            eprintln!(
                "SEND_MORE_EXTENDED: num_messages={}, num_bytes={}",
                s.num_messages, s.num_bytes
            );
        }
        StellarMessage::Transaction(tx) => {
            eprintln!("TRANSACTION: {:?}", tx);
        }
        StellarMessage::DontHave(dh) => {
            eprintln!("DONT_HAVE: type={:?}, hash={:?}", dh.type_, dh.req_hash);
        }
        StellarMessage::Peers(peers) => {
            eprintln!("PEERS: count={}", peers.len());
        }
        StellarMessage::GetTxSet(hash) => {
            eprintln!("GET_TX_SET: hash={:?}", hash);
        }
        StellarMessage::TxSet(set) => {
            eprintln!("TX_SET: previous_ledger={:?}", set.previous_ledger_hash);
        }
        StellarMessage::GeneralizedTxSet(set) => {
            eprintln!("GENERALIZED_TX_SET: {:?}", set);
        }
        StellarMessage::GetScpQuorumset(hash) => {
            eprintln!("GET_SCP_QUORUMSET: hash={:?}", hash);
        }
        StellarMessage::ScpQuorumset(qs) => {
            eprintln!("SCP_QUORUMSET: threshold={}", qs.threshold);
        }
        StellarMessage::ScpMessage(scp) => {
            eprintln!("SCP_MESSAGE: slot={}", scp.statement.slot_index);
        }
        StellarMessage::GetScpState(ledger) => {
            eprintln!("GET_SCP_STATE: ledger={}", ledger);
        }
        StellarMessage::FloodAdvert(advert) => {
            eprintln!("FLOOD_ADVERT: tx_hashes count={}", advert.tx_hashes.len());
        }
        StellarMessage::FloodDemand(demand) => {
            eprintln!("FLOOD_DEMAND: tx_hashes count={}", demand.tx_hashes.len());
        }
        StellarMessage::TimeSlicedSurveyRequest(_) => {
            eprintln!("TIME_SLICED_SURVEY_REQUEST");
        }
        StellarMessage::TimeSlicedSurveyResponse(_) => {
            eprintln!("TIME_SLICED_SURVEY_RESPONSE");
        }
        StellarMessage::TimeSlicedSurveyStartCollecting(_) => {
            eprintln!("TIME_SLICED_SURVEY_START_COLLECTING");
        }
        StellarMessage::TimeSlicedSurveyStopCollecting(_) => {
            eprintln!("TIME_SLICED_SURVEY_STOP_COLLECTING");
        }
    }
}
