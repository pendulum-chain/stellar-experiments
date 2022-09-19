mod connection;
pub mod helper;
pub mod node;

#[macro_use]
pub mod xdr_converter;

use std::collections::HashMap;
pub use connection::*;

use crate::node::NodeInfo;
use crate::xdr_converter::{get_xdr_message_length, parse_authenticated_message};
use stellar::types::StellarMessage;
use substrate_stellar_sdk as stellar;
use substrate_stellar_sdk::network::Network;
use substrate_stellar_sdk::types::{LedgerHeader, ScpStatementPledges, TransactionSet, Uint256};
use substrate_stellar_sdk::{SecretKey, TransactionEnvelope, XdrCodec};

use crate::async_ops::{connect, ConnectionState, UserControls};
use crate::helper::hash;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let network = Network::new(b"Public Global Stellar Network ; September 2015");

    let secret =
        SecretKey::from_encoding("SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73")
            .unwrap();

    let node_info = NodeInfo::new(
        19,
        21,
        19,
        "v19.1.0".to_string(),
        &network,
    );

    let cfg = Config::new("135.181.16.110", 11625, secret, 0, false, true, false);

    let mut user: UserControls = connect(node_info, cfg).await?;


    let mut counter = 0;
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
                ConnectionState::Data(p_id, msg) => match &msg {
                    StellarMessage::ScpMessage(env) => {
                        if counter == 0 {
                            let slot = env.statement.slot_index;

                            match &env.statement.pledges {
                                ScpStatementPledges::ScpStExternalize(x) => {
                                    let scp_value = x.commit.value.get_vec();
                                    // println!("scp_value: {:?}", scp_value);

                                    let scp_value = parse_stellar_type!(scp_value, StellarValue)?;
                                    let tx_hash = scp_value.tx_set_hash;
                                    user.send(StellarMessage::GetTxSet(tx_hash)).await?;

                                    println!("\n pid: {:?} let's see: slot {:?}, tx_set_hash: {:?}", p_id, slot,tx_hash);
                                    counter+= 1;
                                }
                                _ => {}
                            }

                        }
                    }
                    StellarMessage::TxSet(set) => {
                        // println!("The set: {:?} prev_ledger_hash: {:?}", set.txes.len(), set.previous_ledger_hash);

                        let set_xdr = hash(&msg.to_xdr());

                        println!("\nRECEIVED The set: {:?}\n", set_xdr);

                        // let x = set.txes.get_vec();
                        // let wee = x.iter().map(|env| {
                        //    let hash = env.get_hash(&network);
                        //     (hash,slot)
                        // }).collect();
                    }
                    other => {

                        //log::info!("\npid: {:?}  --> {:?}", p_id, other);
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
