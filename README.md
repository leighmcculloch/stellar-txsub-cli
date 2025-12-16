# stellar-overlay

A Rust library and CLI tools for interacting with the Stellar network via the peer-to-peer overlay protocol.

## stellar-overlay (library)

[![Docs](https://img.shields.io/badge/docs-latest-blue)](https://leighmcculloch.github.io/stellar-overlay/)

A Rust library for connecting to and communicating with Stellar Core nodes via the peer-to-peer overlay protocol.

### Features

- Connect to Stellar Core nodes
- Perform authenticated handshakes
- Send and receive protocol messages (transactions, SCP messages, surveys, etc.)

### Example

```rust
use stellar_overlay::connect;
use stellar_xdr::curr::{Hash, StellarMessage, TransactionEnvelope, ReadXdr, Limits};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to a Stellar Core node
    let stream = TcpStream::connect("core-testnet1.stellar.org:11625").await?;

    // Network ID is the SHA-256 hash of the network passphrase
    // This is the testnet network ID
    let network_id = Hash(bytes_lit::bytes!(
        0xcee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472
    ));

    // Perform authenticated handshake
    let mut session = connect(stream, network_id).await?;
    println!("Connected to peer: {:?}", session.peer_info().node_id);

    // Send a transaction
    let tx_xdr = "AAAAAgAAAA...";
    let tx = TransactionEnvelope::from_xdr_base64(tx_xdr, Limits::none())?;
    session.send_message(StellarMessage::Transaction(tx)).await?;

    // Receive messages from the peer
    let msg = session.recv().await?;
    println!("Received: {:?}", msg);

    Ok(())
}
```

## CLI Tools

This repository includes two CLI tools built on top of the stellar-overlay library:

### [stellar-txsub-cli](./stellar-txsub-cli/)

Submit transactions to the Stellar network via the peer-to-peer overlay protocol.

```
echo "AAAAAgAAAA..." | stellar-txsub --network testnet
```

### [stellar-peerinfo-cli](./stellar-peerinfo-cli/)

Get peer information from the Stellar network.

```
stellar-peerinfo --network testnet
```

## Install CLI Tools

```
# Install stellar-txsub
cargo install --locked \
  --git https://github.com/leighmcculloch/stellar-txsub-cli \
  --package stellar-txsub-cli \
  --branch main

# Install stellar-peerinfo
cargo install --locked \
  --git https://github.com/leighmcculloch/stellar-txsub-cli \
  --package stellar-peerinfo-cli \
  --branch main
```

## Networks
See [Stellar Networks](https://developers.stellar.org/docs/networks).
