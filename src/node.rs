use substrate_stellar_sdk::network::Network;

pub type NetworkId = [u8; 32];

pub struct NodeInfo {
    pub ledger_version: u32,
    pub overlay_version: u32,
    pub overlay_min_version: u32,
    pub version_str: String,
    network: Network,
}

impl NodeInfo {
    pub fn new(
        ledger_version: u32,
        overlay_version: u32,
        overlay_min_version: u32,
        version_str: String,
        network: Network,
    ) -> NodeInfo {
        NodeInfo {
            ledger_version,
            overlay_version,
            overlay_min_version,
            version_str,
            network,
        }
    }
    pub fn network_id(&self) -> &NetworkId {
        self.network.get_id()
    }
}
