use std::collections::HashMap;

use stellar_oracle::parse_stellar_type;

use stellar_oracle::helper::compute_non_generic_tx_set_content_hash;
use stellar_oracle::node::NodeInfo;
use stellar_oracle::ConnConfig;
use stellar_oracle::{connect, ConnectionState, UserControls};

use stellar_oracle::sdk as stellar_sdk;
use stellar_sdk::network::Network;
use stellar_sdk::types::StellarMessage;
use stellar_sdk::types::{LedgerHeader, ScpStatementPledges, TransactionSet, Uint256};
use stellar_sdk::{SecretKey, TransactionEnvelope, XdrCodec};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let network = Network::new(b"Public Global Stellar Network ; September 2015");

    let secret =
        SecretKey::from_encoding("SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73")
            .unwrap();

    let node_info = NodeInfo::new(19, 21, 19, "v19.1.0".to_string(), &network);

    let cfg = ConnConfig::new("135.181.16.110", 11625, secret, 0, false, true, false);

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
                ConnectionState::Data {
                    p_id,
                    msg_type,
                    msg,
                } => match &msg {
                    StellarMessage::ScpMessage(env) => {
                        let slot = env.statement.slot_index;

                        match &env.statement.pledges {
                            ScpStatementPledges::ScpStExternalize(x) => {
                                let scp_value = x.commit.value.get_vec();

                                let scp_value = parse_stellar_type!(scp_value, StellarValue)?;
                                let tx_hash = scp_value.tx_set_hash;
                                user.send(StellarMessage::GetTxSet(tx_hash)).await?;

                                println!(
                                    "\n pid: {:?} let's see: slot {:?}, tx_set_hash: {:?}",
                                    p_id, slot, tx_hash
                                );
                                counter += 1;
                            }
                            _ => {}
                        }
                    }
                    StellarMessage::TxSet(set) => {
                        // println!("The set: {:?} prev_ledger_hash: {:?}", set.txes.len(), set.previous_ledger_hash);

                        let set_xdr = compute_non_generic_tx_set_content_hash(&set);

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
