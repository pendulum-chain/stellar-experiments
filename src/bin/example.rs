use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::Split;
use substrate_stellar_sdk::network::Network;
use substrate_stellar_sdk::types::{
    MessageType, ScpEnvelope, ScpStatementExternalize, ScpStatementPledges, StellarMessage,
    TransactionSet, Uint64,
};
use substrate_stellar_sdk::{Hash, SecretKey, XdrCodec};

use stellar_relay::helper::{compute_non_generic_tx_set_content_hash, time_now};
use stellar_relay::node::NodeInfo;
use stellar_relay::{
    connect, parse_stellar_type, ConnConfig, Error, StellarNodeMessage, UserControls,
};

pub type Slot = Uint64;
pub type SlotEncodedMap = BTreeMap<Slot, Vec<u8>>;
pub type TxSetCheckerMap = HashMap<Hash, Slot>;

pub type EnvelopesMap = BTreeMap<Slot, Vec<ScpEnvelope>>;
pub type TxSetMap = BTreeMap<Slot, TransactionSet>;
pub type TxHashMap = (String, HashMap<Hash, Slot>);

use substrate_stellar_sdk::compound_types::UnlimitedVarArray;
use substrate_stellar_sdk::types::MessageType::TxSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub trait FileHandler<T: Default> {
    const PATH: &'static str;
    fn write_to_file(value: Self) -> Result<String, Error>;
    fn deserialize_bytes(bytes: Vec<u8>) -> T;
    fn check_slot_in_splitted_filename(slot_param: Slot, splits: &mut Split<&str>) -> bool;

    fn get_path(filename: &str) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(Self::PATH);
        path.push(filename);
        path
    }

    fn read_file(filename: String) -> T {
        let path = Self::get_path(&filename);

        match File::open(path) {
            Ok(mut file) => {
                let mut bytes: Vec<u8> = vec![];
                let read_size = file.read_to_end(&mut bytes).unwrap_or_else(|e| {
                    log::warn!("error reading from file: {:?}", e);
                    0
                });

                if read_size > 0 {
                    return Self::deserialize_bytes(bytes);
                }
            }
            Err(e) => {
                log::warn!("error occurred when reading from file: {:?}", e);
            }
        }

        T::default()
    }

    fn write_data_to_file<S: ?Sized + Serialize>(filename: &str, data: &S) -> Result<(), Error> {
        let res = bincode::serialize(data).map_err(|e| Error::Undefined(e.to_string()))?;
        let mut path = Self::get_path(filename);
        let mut file = File::create(path).map_err(|e| Error::Undefined(e.to_string()))?;

        file.write_all(&res)
            .map_err(|e| Error::Undefined(e.to_string()))
    }

    fn find_file_by_slot(slot_param: Slot) -> Result<String, Error> {
        let paths = fs::read_dir(Self::PATH).map_err(|e| Error::Undefined(e.to_string()))?;

        for path in paths {
            let filename = path
                .map_err(|e| Error::Undefined(e.to_string()))?
                .file_name()
                .into_string()
                .unwrap();
            let mut splits = filename.split("_");

            if Self::check_slot_in_splitted_filename(slot_param, &mut splits) {
                return Ok(filename);
            }
        }

        Err(Error::Undefined(format!(
            "Cannot find file for slot {}",
            slot_param
        )))
    }
}

pub const MAX_SLOTS_PER_FILE: Uint64 = 5;
pub const MIN_EXTERNALIZED_MESSAGES: usize = 10;

pub const MAX_TXS_PER_FILE: Uint64 = 3000;

impl FileHandler<Self> for EnvelopesMap {
    const PATH: &'static str = "./scp_envelopes";

    fn write_to_file(value: Self) -> Result<String, Error> {
        let mut filename: String = "".to_string();
        let mut m: SlotEncodedMap = SlotEncodedMap::new();

        for (idx, (key, value)) in value.into_iter().enumerate() {
            if idx == 0 {
                filename.push_str(&format!("{}_{}.json", key, time_now()));
            }

            let stellar_array = UnlimitedVarArray::new(value)?;
            m.insert(key, stellar_array.to_xdr());
        }

        Self::write_data_to_file(&filename, &m)?;
        Ok(filename)
    }

    fn deserialize_bytes(bytes: Vec<u8>) -> Self {
        let inside: SlotEncodedMap = bincode::deserialize(&bytes).unwrap_or(SlotEncodedMap::new());

        let mut m: EnvelopesMap = EnvelopesMap::new();

        for (key, value) in inside.into_iter() {
            if let Ok(envelopes) = UnlimitedVarArray::<ScpEnvelope>::from_xdr(value) {
                m.insert(key, envelopes.get_vec().to_vec());
            }
        }

        m
    }

    fn check_slot_in_splitted_filename(slot_param: Slot, splits: &mut Split<&str>) -> bool {
        if let Some(slot) = splits.next() {
            log::info!("THE SLOT? {}", slot);

            match slot.parse::<Uint64>() {
                Ok(slot_num) => {
                    if slot_param >= slot_num && slot_param <= slot_num + MAX_SLOTS_PER_FILE {
                        // we found it! return this one
                        log::info!("we found it!");
                        return true;
                    }
                }
                Err(_) => {
                    log::warn!("unconventional named file.");
                    return false;
                }
            }
        }

        false
    }
}

impl FileHandler<Self> for TxSetMap {
    const PATH: &'static str = "./tx_sets";

    fn write_to_file(value: Self) -> Result<String, Error> {
        let mut filename: String = "".to_string();
        let mut m: SlotEncodedMap = SlotEncodedMap::new();
        let len = value.len();

        for (idx, (key, set)) in value.into_iter().enumerate() {
            if idx == 0 {
                filename.push_str(&format!("{}_", key));
            }

            if idx == (len - 1) {
                filename.push_str(&format!("{}_{}.json", key, time_now()));
            }

            m.insert(key, set.to_xdr());
        }

        Self::write_data_to_file(&filename, &m)?;
        Ok(filename)
    }

    fn deserialize_bytes(bytes: Vec<u8>) -> TxSetMap {
        let inside: SlotEncodedMap = bincode::deserialize(&bytes).unwrap_or(SlotEncodedMap::new());

        let mut m: TxSetMap = TxSetMap::new();

        for (key, value) in inside.into_iter() {
            if let Ok(set) = TransactionSet::from_xdr(value) {
                m.insert(key, set);
            }
        }

        m
    }

    fn check_slot_in_splitted_filename(slot_param: Slot, splits: &mut Split<&str>) -> bool {
        fn parse_slot(slot_opt: Option<&str>) -> Option<Slot> {
            (slot_opt?)
                .parse::<Slot>()
                .map_err(|e| {
                    log::warn!("Unconventional file name: {:?}", e);
                    e
                })
                .ok()
        }

        if let Some(start_slot) = parse_slot(splits.next()) {
            if let Some(end_slot) = parse_slot(splits.next()) {
                return (slot_param >= start_slot) && (slot_param <= end_slot);
            }
        }

        false
    }
}

impl FileHandler<HashMap<Hash, Slot>> for TxHashMap {
    const PATH: &'static str = "./tx_hashes";

    fn write_to_file(value: Self) -> Result<String, Error> {
        Self::write_data_to_file(&value.0, &value.1)?;
        Ok(value.0)
    }

    fn deserialize_bytes(bytes: Vec<u8>) -> HashMap<Hash, Slot> {
        bincode::deserialize(&bytes).unwrap_or(HashMap::new())
    }

    fn check_slot_in_splitted_filename(slot_param: Slot, splits: &mut Split<&str>) -> bool {
        TxSetMap::check_slot_in_splitted_filename(slot_param, splits)
    }
}

pub struct ScpMessageCollector {
    envelopes_map: EnvelopesMap,
    txset_map: TxSetMap,
    tx_hash_map: HashMap<Hash, Slot>,
    network: Network,
}

impl ScpMessageCollector {
    pub fn new(network: Network) -> Self {
        ScpMessageCollector {
            envelopes_map: Default::default(),
            txset_map: Default::default(),
            tx_hash_map: Default::default(),
            network,
        }
    }

    async fn handle_envelope(
        &mut self,
        env: ScpEnvelope,
        txset_hash_map: &mut TxSetCheckerMap,
        user: &UserControls,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let slot = env.statement.slot_index;

        if let ScpStatementPledges::ScpStExternalize(stmt) = &env.statement.pledges {
            let txset_hash = get_tx_set_hash(stmt)?;

            if let None = txset_hash_map.get(&txset_hash) {
                // let's check whether this is a delayed message.
                if !self.txset_map.contains_key(&slot) {
                    // we're creating a new entry
                    txset_hash_map.insert(txset_hash, slot);
                    user.send(StellarMessage::GetTxSet(txset_hash)).await?;

                    // check if we need to write to file
                    self.check_write_envelopes_to_file()?;
                }
            }

            // insert/add messages
            match self.envelopes_map.get_mut(&slot) {
                None => {
                    log::info!("slot: {} add to envelopes map", slot);

                    self.envelopes_map.insert(slot, vec![env]);
                }
                Some(value) => {
                    log::debug!("slot: {} insert to envelopes map", slot);
                    value.push(env);
                }
            }
        }

        Ok(())
    }

    fn check_write_envelopes_to_file(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut keys = self.envelopes_map.keys();
        let keys_len = u64::try_from(keys.len()).unwrap_or(0);

        // map is too small; we don't have to write it to file just yet.
        if keys_len < MAX_SLOTS_PER_FILE {
            return Ok(());
        }

        log::debug!("The map is getting big. Let's write to file:");

        // only write a max of MAX_SLOTS_PER_FILE entries.
        let mut counter = 0;

        while let Some(key) = keys.next() {
            // save to file if all data for the corresponding slots have been filled.
            if counter == MAX_SLOTS_PER_FILE {
                self.write_envelopes_to_file(*key)?;
                break;
            }

            if let Some(value) = self.envelopes_map.get(key) {
                // check if we have enough externalized messages for the corresponding key
                if value.len() < MIN_EXTERNALIZED_MESSAGES {
                    if keys_len > MAX_SLOTS_PER_FILE + 1 {
                        println!(
                            "slot: {} we've waited long enough. let's save to file.",
                            key
                        );
                    } else {
                        log::info!("slot: {} not enough messages. Let's wait for more.", key);
                        break;
                    }
                }
            } else {
                // something wrong??? race condition?
                log::error!("slot: {} SOMETHING'S WRONG!", key);
                break;
            }

            counter += 1;
        }

        Ok(())
    }

    fn write_envelopes_to_file(
        &mut self,
        last_slot: Slot,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let new_slot_map = self.envelopes_map.split_off(&last_slot);
        log::info!(
            "saving old envelopes to file: {:?}",
            self.envelopes_map.keys()
        );

        EnvelopesMap::write_to_file(self.envelopes_map.clone())?;
        self.envelopes_map = new_slot_map;
        log::info!("start slot is now: {:?}", last_slot);

        Ok(())
    }

    fn handle_tx_set(
        &mut self,
        set: &TransactionSet,
        txset_hash_map: &mut TxSetCheckerMap,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.check_write_tx_set_to_file()?;

        // compute the tx_set_hash, to check what slot this set belongs too.
        let tx_set_hash = compute_non_generic_tx_set_content_hash(set);

        if let Some(slot) = txset_hash_map.remove(&tx_set_hash) {
            log::info!("slot: {} insert tx_set_hash", slot);
            self.txset_map.insert(slot, set.clone());
            self.update_tx_hash_map(slot, set);
        } else {
            log::info!("WARNING! tx_set_hash: {:?} has no slot.", tx_set_hash);
        }

        Ok(())
    }

    fn check_write_tx_set_to_file(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // map is too small; we don't have to write it to file just yet.
        if self.tx_hash_map.len() < usize::try_from(MAX_TXS_PER_FILE).unwrap_or(0) {
            return Ok(());
        }

        log::info!(
            "saving old transactions to file: {:?}",
            self.txset_map.keys()
        );

        let file_name = TxSetMap::write_to_file(self.txset_map.clone())?;
        TxHashMap::write_to_file((file_name, self.tx_hash_map.clone()))?;

        self.txset_map = TxSetMap::new();
        self.tx_hash_map = HashMap::new();

        Ok(())
    }

    fn update_tx_hash_map(&mut self, slot: Slot, set: &TransactionSet) {
        set.txes.get_vec().iter().for_each(|tx_env| {
            let tx_hash = tx_env.get_hash(&self.network);
            self.tx_hash_map.insert(tx_hash, slot);
        });
    }
}

fn get_tx_set_hash(
    x: &ScpStatementExternalize,
) -> Result<Hash, stellar_relay::xdr_converter::Error> {
    let scp_value = x.commit.value.get_vec();
    parse_stellar_type!(scp_value, StellarValue).map(|scp_value| scp_value.tx_set_hash)
}

/*
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let slot = 42784130;
    if let Ok(file) = EnvelopesMap::find_file_by_slot(slot) {
        println!("the filename:: {:?}", file);
        let result = EnvelopesMap::deserialize(file);
        println!("\nenvelopesmap: {:?}", result.get(&slot));
    }

    if let Ok(file) = TxHashMap::find_file_by_slot(slot) {
        println!("\n\nthe filename: {:?}", file);

        let result = TxHashMap::deserialize(file.clone());
        println!("\nhashmap: {:?}", result.keys());


        let result = TxSetMap::deserialize(file.clone());
        println!("\ntxset: {:?}", result.get(&slot));
    }

    Ok(())
}
*/

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    fs::create_dir_all("./scp_envelopes")?;
    fs::create_dir_all("./tx_sets")?;
    fs::create_dir_all("./tx_hashes")?;

    let network = Network::new(b"Public Global Stellar Network ; September 2015");

    let secret =
        SecretKey::from_encoding("SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73")
            .unwrap();

    let node_info = NodeInfo::new(19, 21, 19, "v19.1.0".to_string(), &network);

    let cfg = ConnConfig::new("135.181.16.110", 11625, secret, 0, false, true, false);

    let mut user: UserControls = connect(node_info, cfg).await?;

    let mut collector = ScpMessageCollector::new(network);

    // just a temporary holder
    let mut tx_set_hash_map: HashMap<Hash, Slot> = HashMap::new();

    while let Some(conn_state) = user.recv().await {
        match conn_state {
            StellarNodeMessage::Data {
                p_id,
                msg_type,
                msg,
            } => match msg {
                StellarMessage::ScpMessage(env) => {
                    collector
                        .handle_envelope(env, &mut tx_set_hash_map, &user)
                        .await?;
                }
                StellarMessage::TxSet(set) => {
                    collector.handle_tx_set(&set, &mut tx_set_hash_map)?;
                }
                _ => {}
            },

            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {}
