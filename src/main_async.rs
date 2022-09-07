mod connection;
pub mod helper;
pub mod node;
pub mod xdr_converter;

pub use connection::*;
use std::fs::read;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::node::NodeInfo;
use crate::xdr_converter::{get_xdr_message_length, parse_authenticated_message};
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

use crate::async_ops::{connect, ConnectionState};
use tokio::sync::mpsc;

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

        async_ops::Connector::new(node_info, secret, 0, false)
    };
    let addr = "135.181.16.110:11625";

    let mut user_controls = connect(cfg, addr).await?;

    loop {

        if let Some(conn_state) = user_controls.recv().await {
            match conn_state {
                ConnectionState::Connect { pub_key, node_info } => {
                    println!("Connected to Stellar Node: {:?}", String::from_utf8(pub_key.to_encoding()).unwrap());
                    println!("{:?}",node_info);

                    user_controls.send(StellarMessage::GetScpState(0)).await?;
                }
                ConnectionState::Data(p_id, msg) => {

                    match msg {
                        StellarMessage::ScpMessage(env) => {
                            println!("pid: {:?}  --> {:?}", p_id, env.statement.pledges);
                        }
                        other => {
                            println!("pid: {:?}  --> other: {:?}", p_id, other);
                        }
                    }

                }
                ConnectionState::Error(_) => {}
                ConnectionState::Timeout => {
                    return Ok(());
                }
            }

        }
    }
}
