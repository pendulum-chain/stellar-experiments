use substrate_stellar_sdk::{network::PUBLIC_NETWORK, SecretKey, types::{ScpStatementExternalize, ScpStatementPledges, StellarMessage}};
use substrate_stellar_sdk::Hash;

use crate::{ConnConfig, node::NodeInfo, StellarNodeMessage, UserControls};

const TIER_1_VALIDATOR_IP_PUBLIC: &str = "51.161.197.48";

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
    let mut received_message = false;
    while attempts < max_attempts {
        match overlay_connection.recv().await {
            None => {}
            Some(message) => {
                if let StellarNodeMessage::Connect { pub_key: x, node_info: y } = message {
                    assert_eq!(y.ledger_version, node_info.ledger_version);
                }
                received_message = true;
                break;
            }
        }
        attempts += 1;
    }
    assert_eq!(received_message, true);
}

#[tokio::test]
async fn stellar_overlay_should_receive_scp_messages() {
    //arrange
    let secret =
        SecretKey::from_encoding("SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73")
            .unwrap();

    let node_info = NodeInfo::new(19, 25, 23, "v19.5.0".to_string(), &PUBLIC_NETWORK);
    //act
    let cfg = ConnConfig::new(TIER_1_VALIDATOR_IP_PUBLIC, 11625, secret, 0, false, true, false);
    let mut overlay_connection = UserControls::connect(node_info.clone(), cfg).await.unwrap();

    let max_attempts = 100;
    let mut attempts = 0;
    let mut received_scp_message = false;
    while attempts < max_attempts {
        attempts += 1;
        match overlay_connection.recv().await {
            None => {}
            Some(message) => {
                match message {
                    StellarNodeMessage::Data { p_id, msg_type, msg } => match msg {
                        StellarMessage::ScpMessage(msg) => {
                            received_scp_message = true;
                            break;
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }


    //assert
    //ensure that we receive some scp message from stellar node
    assert_eq!(received_scp_message, true);
}

#[tokio::test]
async fn stellar_overlay_should_receive_tx_set() {
    //arrange
    pub fn get_tx_set_hash(x: &ScpStatementExternalize) -> Hash {
        let scp_value = x.commit.value.get_vec();
        return scp_value[0..32].try_into().unwrap();
    }

    let secret =
        SecretKey::from_encoding("SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73")
            .unwrap();

    let node_info = NodeInfo::new(19, 25, 23, "v19.5.0".to_string(), &PUBLIC_NETWORK);
    let cfg = ConnConfig::new(TIER_1_VALIDATOR_IP_PUBLIC, 11625, secret, 0, true, true, false);
    //act
    let mut overlay_connection = UserControls::connect(node_info.clone(), cfg).await.unwrap();

    let mut tx_set_vec = vec![];
    let mut attempt = 0;
    while let Some(relay_message) = overlay_connection.recv().await {
        if attempt > 300 {
            break;
        }
        attempt = attempt + 1;
        match relay_message {
            StellarNodeMessage::Data { p_id, msg_type, msg } => match msg {
                StellarMessage::ScpMessage(msg) => {
                    if let ScpStatementPledges::ScpStExternalize(stmt) = &msg.statement.pledges {
                        let txset_hash = get_tx_set_hash(stmt);
                        overlay_connection.send(StellarMessage::GetTxSet(txset_hash)).await.unwrap();
                    }
                }
                StellarMessage::TxSet(set) => {
                    tx_set_vec.push(set);
                    break;
                }
                _ => {}
            },
            _ => {}
        }
    }
    //arrange
    //ensure that we receive some tx set from stellar node
    assert!(tx_set_vec.len() > 0);
}
