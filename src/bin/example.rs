use std::collections::HashMap;

use stellar_oracle::helper::compute_non_generic_tx_set_content_hash;
use stellar_oracle::node::NodeInfo;
use stellar_oracle::ConnConfig;
use stellar_oracle::{connect, parse_stellar_type};
use stellar_oracle::{StellarNodeMessage, UserControls};

use stellar_oracle::sdk as stellar_sdk;
use stellar_sdk::network::Network;
use stellar_sdk::types::StellarMessage;
use stellar_sdk::types::{LedgerHeader, ScpStatementPledges, TransactionSet, Uint256};
use stellar_sdk::{SecretKey, TransactionEnvelope, XdrCodec};
use substrate_stellar_sdk::types::{ScpStatementExternalize, Uint64};
use substrate_stellar_sdk::Hash;

fn hash_str(hash: &[u8]) -> String {
    base64::encode(hash)
}

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

    // just a temporary holder
    let mut tx_set_hash_map: HashMap<Hash, Uint64> = HashMap::new();

    // final maps
    // todo: if there is no issue/redeem request,then we don't have to store it.
    // for now, just store everything
    let mut slot_hash_map: HashMap<Uint64, (Vec<ScpStatementExternalize>, Option<TransactionSet>)> =
        HashMap::new();
    let mut tx_hash_map: HashMap<Hash, Uint64> = HashMap::new();

    loop {
        if let Some(conn_state) = user.recv().await {
            match conn_state {
                StellarNodeMessage::Connect { pub_key, node_info } => {
                    log::info!(
                        "Connected to Stellar Node: {:?}",
                        String::from_utf8(pub_key.to_encoding()).unwrap()
                    );
                    log::info!("{:?}", node_info);

                    user.send(StellarMessage::GetScpState(0)).await?;
                }
                StellarNodeMessage::Data {
                    p_id,
                    msg_type,
                    msg,
                } => {
                    match &msg {
                        StellarMessage::ScpMessage(env) => match &env.statement.pledges {
                            ScpStatementPledges::ScpStExternalize(x) => {
                                let slot = env.statement.slot_index;

                                let scp_value = x.commit.value.get_vec();

                                let scp_value = parse_stellar_type!(scp_value, StellarValue)?;
                                let tx_hash = scp_value.tx_set_hash;

                                println!("\npid: {:?} let's see: slot {:?} node_id {:?}, tx_set_hash: {:?}, quorum_set_hash: {:?}",
                                         p_id, slot,
                                         env.statement.node_id, hash_str(&tx_hash),
                                         hash_str(&x.commit_quorum_set_hash)
                                );

                                if let None = tx_set_hash_map.get(&tx_hash) {
                                    tx_set_hash_map.insert(tx_hash, slot);
                                    user.send(StellarMessage::GetTxSet(tx_hash)).await?;
                                }

                                let _ = slot_hash_map
                                    .entry(slot)
                                    .and_modify(|value| {
                                        (*value).0.push(x.clone());
                                    })
                                    .or_insert((vec![x.clone()], None));
                            }
                            _ => {
                                println!("\n pid: {:?} continue...", p_id);
                            }
                        },
                        StellarMessage::TxSet(set) => {
                            // println!("The set: {:?} prev_ledger_hash: {:?}", set.txes.len(), set.previous_ledger_hash);

                            let tx_set_hash = compute_non_generic_tx_set_content_hash(&set);

                            if let Some(slot) = tx_set_hash_map.get(&tx_set_hash) {
                                let _ = slot_hash_map.entry(*slot).and_modify(|value| {
                                    (*value).1 = Some(set.clone());
                                });

                                println!("\npid: {:?} This tx set:: {:?} belongs to slot {} with size: {:?}", p_id, hash_str(&tx_set_hash), slot, set.txes.len());
                            } else {
                                println!("\npid: {:?} This tx set:: {:?} belongs to no slot with size: {:?}", p_id, hash_str(&tx_set_hash), set.txes.len());
                            }

                            // let x = set.txes.get_vec();
                            // let wee = x.iter().map(|env| {
                            //    let hash = env.get_hash(&network);
                            //     (hash,slot)
                            // }).collect();
                        }
                        other => {
                            println!("\n pid: {:?} continue...", p_id);
                            //log::info!("\npid: {:?}  --> {:?}", p_id, other);
                        }
                    }
                }
                StellarNodeMessage::Error(_) => {}
                StellarNodeMessage::Timeout => {
                    return Ok(());
                }
            }
        }
    }
}
