mod connection;
pub mod helper;
pub mod node;
pub mod xdr_converter;

pub use connection::*;
use std::fs::read;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::node::NodeInfo;
use crate::xdr_converter::{get_message_length, parse_authenticated_message};
use hmac::Hmac;
use stellar::compound_types::LimitedString;
use stellar::types::{
    Auth, AuthCert, AuthenticatedMessage, AuthenticatedMessageV0, Curve25519Public, Error, Hello,
    HmacSha256Mac, SendMore, Signature, StellarMessage, Uint256,
};
use stellar::{Curve25519Secret, PublicKey, XdrCodec};
use substrate_stellar_sdk as stellar;
use substrate_stellar_sdk::network::Network;
use substrate_stellar_sdk::SecretKey;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::async_ops::connect;
use tokio::sync::mpsc;

pub struct Config {
    secret_key: SecretKey,
    secret_key_ecdh: String,
    auth_time: u64,
    connection_local_nonce: String,
    node_info: NodeInfo,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cfg = {
        let secret =
            SecretKey::from_encoding("SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73")
                .unwrap();

        let node_info = NodeInfo::new(
            19,
            21,
            19,
            "v19.1.0".to_string(),
            &Network::new(b"Public Global Stellar Network ; September 2015"),
        );

        async_ops::ConnectionConfig::new(node_info, secret, 0, false)
    };
    let addr = "135.181.16.110:11625";

    let mut user_controls = connect(cfg, addr).await?;


    let what_to_do = |msg: StellarMessage| {
        // handle the messages you receive, here.
        println!(
            "\nreceived message:\n------------------\n{:?}\n------------------\n",
            msg
        );
    };

    let mut counter = 0;
    loop {
        if counter == 1 {
            // this is just an example message I send to the Stellar Node.
            user_controls.send(StellarMessage::GetPeers).await?;
        }

        if user_controls.is_handshake_complete() {
            counter += 1;
        }

        user_controls.recv(what_to_do).await?;
    }
}
