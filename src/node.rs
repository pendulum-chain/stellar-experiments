use substrate_stellar_sdk::network::Network;

pub type NetworkId = [u8;32];

pub struct NodeInfo {
    pub ledger_version: u32,
    pub overlay_version: u32,
    pub overlay_min_version: u32,
    pub version_str: String,
    network: Network
}

impl NodeInfo {
    pub fn network_id(&self) -> &NetworkId {
        self.network.get_id()
    }
}