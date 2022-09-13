mod connection;
pub mod helper;
pub mod node;

#[macro_use]
pub mod xdr_converter;

pub use connection::*;

use crate::node::NodeInfo;
use crate::xdr_converter::{get_xdr_message_length, parse_authenticated_message};
use stellar::types::StellarMessage;
use substrate_stellar_sdk as stellar;
use substrate_stellar_sdk::network::Network;
use substrate_stellar_sdk::types::ScpStatementPledges;
use substrate_stellar_sdk::SecretKey;

use crate::async_ops::{connect, ConnectionState, UserControls};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

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

    let cfg = Config::new("135.181.16.110", 11625, secret, 0, false, true, false);

    let mut user: UserControls = connect(node_info, cfg).await?;

    loop {
        if let Some(conn_state) = user.recv().await {
            match conn_state {
                ConnectionState::Connect { pub_key, node_info } => {
                    log::info!(
                        "Connected to Stellar Node: {:?}",
                        String::from_utf8(pub_key.to_encoding()).unwrap()
                    );
                    log::info!("{:?}", node_info);

                    user.send(StellarMessage::GetScpState(0)).await?;
                }
                ConnectionState::Data(p_id, msg) => match msg {
                    StellarMessage::ScpMessage(env) => {
                        log::info!("\npid: {:?}  --> {:?}", p_id, env.statement.pledges);
                    }
                    other => {
                        log::info!("\npid: {:?}  --> {:?}", p_id, other);
                    }
                },
                ConnectionState::Error(_) => {}
                ConnectionState::Timeout => {
                    return Ok(());
                }
            }
        }
    }
}
