use substrate_stellar_sdk::{network::PUBLIC_NETWORK, SecretKey, types::{ScpStatementExternalize, ScpStatementPledges, StellarMessage}};
use substrate_stellar_sdk::Hash;

use crate::{ConnConfig, node::NodeInfo, StellarNodeMessage, UserControls};

const TIER_1_VALIDATOR_IP_PUBLIC: &str = "51.161.197.48";

pub fn get_tx_set_hash(x: &ScpStatementExternalize) -> Hash {
    let scp_value = x.commit.value.get_vec();
    return scp_value[0..32].try_into().unwrap();
}

#[tokio::test]
async fn stellar_overlay_connect_and_listen_connect_message() {
    let secret =
        SecretKey::from_encoding("SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73")
            .unwrap();

    let node_info = NodeInfo::new(19, 25, 23, "v19.5.0".to_string(), &PUBLIC_NETWORK);
    let cfg = ConnConfig::new(TIER_1_VALIDATOR_IP_PUBLIC, 11625, secret, 0, false, true, false);
    let mut overlay_connection = UserControls::connect(node_info.clone(), cfg).await.unwrap();

    let max_attempts = 1000;
    let mut attempts = 0;
    let mut received_scp_message = false;
    let mut tx_set_vec = vec![];
    let mut count_check = 0;

    // We are using a while loop here because we don't know exactly in which order the messages will
    // arrive and some of the messages are not relevant to us or empty.
    while attempts < max_attempts {
        match overlay_connection.recv().await {
            None => {}
            Some(message) => {
                match message {
                    StellarNodeMessage::Connect { pub_key, node_info: y } => {
                        assert_eq!(y.ledger_version, node_info.ledger_version);
                        count_check = 1;
                    }
                    StellarNodeMessage::Data { p_id, msg_type, msg } => match msg {
                        StellarMessage::ScpMessage(msg) => {
                            received_scp_message = true;
                            if count_check == 0 {
                                panic!("received a data message before the connect message");
                            }

                            if let ScpStatementPledges::ScpStExternalize(stmt) = &msg.statement.pledges {
                                let txset_hash = get_tx_set_hash(stmt);
                                overlay_connection.send(StellarMessage::GetTxSet(txset_hash)).await.unwrap();
                                count_check = 1;
                            }
                        }
                        StellarMessage::TxSet(set) => {
                            if count_check != 1 {
                                panic!("received a TxSetMessage before requesting one.")
                            }

                            tx_set_vec.push(set);
                            count_check = 2;
                            break;
                        }
                        _ => {}
                    },

                    _ => {}
                }
            }
        }
        attempts += 1;
    }
    // We should have received a SCP message and a TxSet message.
    assert_eq!(count_check, 2);
    assert_eq!(received_scp_message, true);
    assert!(tx_set_vec.len() > 0);
}
