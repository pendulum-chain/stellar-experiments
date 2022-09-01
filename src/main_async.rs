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


use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;

use tokio::sync::mpsc;
use crate::async_ops::initialize;
use connection::async_ops::config::{ConnectionConfig};

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

        let secret = stellar::SecretKey::from_encoding(
            "SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73",
        )
            .unwrap();

        let node_info = NodeInfo::new(
            19,
            21,
            19,
            "v19.1.0".to_string(),
            &Network::new(b"Public Global Stellar Network ; September 2015"),
        );

        ConnectionConfig::new(
            node_info,
            secret,
            0,
            false,
        )
    };
    let addr = "135.181.16.110:11625";

    let (tx, mut rx) = mpsc::channel::<StellarMessage>(1024);


    let tx_writer = initialize(cfg, addr, tx).await?;

    loop {
        if let Some(msg) = rx.recv().await {
            println!("handle this message: {:?}", msg);

            println!("let's try to sendsome")
        }

    }


}