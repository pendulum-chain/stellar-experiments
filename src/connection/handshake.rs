use substrate_stellar_sdk::compound_types::LimitedString;

use substrate_stellar_sdk::PublicKey;
use substrate_stellar_sdk::types::{AuthCert, Hello, StellarMessage, Uint256};
use crate::node::NodeInfo;

pub fn create_hello_message(
    peer_id: PublicKey,
    nonce: Uint256,
    cert: AuthCert,
    listening_port: u32,
    node_info: &NodeInfo,
) -> StellarMessage {

    let version_str = &node_info.version_str;
    let hello = Hello {
        ledger_version: node_info.ledger_version,
        overlay_version: node_info.overlay_version,
        overlay_min_version: node_info.overlay_min_version,
        network_id: *node_info.network_id(),
        version_str: LimitedString::<100>::new(version_str.as_bytes().to_vec()).unwrap(),
        listening_port: i32::try_from(listening_port).unwrap(),
        peer_id,
        cert ,
        nonce
    };

    StellarMessage::Hello(hello)
}