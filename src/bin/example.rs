use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use substrate_stellar_sdk::{Hash, SecretKey, XdrCodec};
use substrate_stellar_sdk::network::Network;
use substrate_stellar_sdk::types::{MessageType, ScpEnvelope, ScpStatementExternalize, ScpStatementPledges, StellarMessage, TransactionSet, Uint64};

use stellar_relay::{ConnConfig, connect, Error, parse_stellar_type, StellarNodeMessage, UserControls};
use stellar_relay::helper::{compute_non_generic_tx_set_content_hash, time_now};
use stellar_relay::node::NodeInfo;

pub type Slot = Uint64;
pub type SlotEncodedMap = BTreeMap<Slot,Vec<u8>>;
pub type TxSetCheckerMap = HashMap<Hash,Slot>;

pub type EnvelopesMap = BTreeMap<Slot,Vec<ScpEnvelope>>;
pub type TxSetMap = BTreeMap<Slot,TransactionSet>;
pub type TxHashMap = (String,HashMap<Hash, Slot>);

use substrate_stellar_sdk::compound_types::UnlimitedVarArray;
use substrate_stellar_sdk::types::MessageType::TxSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub trait FileHandler<T>{
    fn write_to_file(value:Self) -> Result<String, Error>;
    fn read_file(filename:String) -> T;
    fn find_file_by_slot(slot_param: Slot) -> Result<String,Error>;
}

pub const MAX_SLOTS_PER_FILE: Uint64 = 5;
pub const MIN_EXTERNALIZED_MESSAGES: usize = 10;

pub const MAX_TXS_PER_FILE:Uint64 = 3000;

impl FileHandler<Self> for EnvelopesMap {
    fn write_to_file(value: Self) -> Result<String, Error> {
        let mut file: File;

        let mut filename: String = "".to_string();
        let mut m: SlotEncodedMap = SlotEncodedMap::new();

        for (idx, (key, value)) in value.into_iter().enumerate() {
            if idx == 0 {
                filename.push_str(&format!("{}_{}.json", key, time_now()));
            }

            let stellar_array = UnlimitedVarArray::new(value)?;

            m.insert(key, stellar_array.to_xdr());
        }

        let res = bincode::serialize(&m)
            .map_err(|e| Error::Undefined(e.to_string()))?;

        let mut path = PathBuf::new();
        path.push("./scp_envelopes");
        path.push(filename.clone());

        file = File::create(path).map_err(|e| Error::Undefined(e.to_string()))?;
        file.write_all(&res).map_err(|e| Error::Undefined(e.to_string()))?;

        Ok(filename)
    }

    fn read_file(filename: String) -> EnvelopesMap {
        let mut m: EnvelopesMap = EnvelopesMap::new();

        let mut path = PathBuf::new();
        path.push("./scp_envelopes");
        path.push(filename);

        if let Ok(mut file) = File::open(path) {
            let mut bytes: Vec<u8> = vec![];
            let read_size = file.read_to_end(&mut bytes)
                .unwrap_or(0);

            if read_size > 0 {
                let inside: SlotEncodedMap = bincode::deserialize(&bytes)
                    .unwrap_or(SlotEncodedMap::new());

                for (key, value) in inside.into_iter() {
                    if let Ok(envelopes) =
                        UnlimitedVarArray::<ScpEnvelope>::from_xdr(value) {
                        m.insert(key,envelopes.get_vec().to_vec());
                    }
                }
            }
        }

        m
    }

    fn find_file_by_slot(slot_param: Slot) -> Result<String,Error> {
        let paths = fs::read_dir("./scp_envelopes")
            .map_err(|e| Error::Undefined(e.to_string()))?;

        for path in paths {
            let filename = path.map_err(|e| Error::Undefined(e.to_string()))?
                .file_name().into_string().unwrap();

            let mut splits = filename.split("_");

            if let Some(slot) = splits.next() {
                log::info!("THE SLOT? {}", slot);
                let slot_num = slot.parse::<Uint64>()
                    .map_err(|e| Error::Undefined(e.to_string()))?;
                if slot_param >= slot_num && slot_param <= slot_num + MAX_SLOTS_PER_FILE {
                    // we found it! return this one
                    log::info!("we found it! return {}", filename);
                    return Ok(filename);
                }
            }
        }

        Err(Error::Undefined(format!("Cannot find file for slot {}", slot_param)))
    }
}

impl FileHandler<Self> for TxSetMap {
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

        let res = bincode::serialize(&m).map_err(|e| Error::Undefined(e.to_string()))?;

        let mut path = PathBuf::new();
        path.push("./tx_sets");
        path.push(filename.clone());

        let mut file = File::create(path).map_err(|e| Error::Undefined(e.to_string()))?;
        file.write(&res).map_err(|e| Error::Undefined(e.to_string()))?;

        Ok(filename)
    }

    fn read_file(filename: String) -> TxSetMap {
        let mut m: TxSetMap = TxSetMap::new();

        let mut path = PathBuf::new();
        path.push("./tx_sets");
        path.push(filename);

        if let Ok(mut file) = File::open(path) {


            let mut bytes: Vec<u8> = vec![];
            let read_size = file.read_to_end(&mut bytes)
                .unwrap_or(0);

            if read_size > 0 {
                let inside: SlotEncodedMap = bincode::deserialize(&bytes)
                    .unwrap_or(SlotEncodedMap::new());

                for (key, value) in inside.into_iter() {
                    if let Ok(set) =
                    TransactionSet::from_xdr(value) {
                        m.insert(key,set);
                    }
                }
            }
        }

        m
    }

    fn find_file_by_slot(slot_param: Slot) -> Result<String,Error> {
        let paths = fs::read_dir("./tx_sets")
            .map_err(|e| Error::Undefined(e.to_string()))?;

        for path in paths {
            let filename = path.map_err(|e| Error::Undefined(e.to_string()))?
                .file_name().into_string().unwrap();
            let mut splits = filename.split("_");

            let start_slot = splits.next().ok_or(Error::Undefined("unconventional file name".to_string()))?;
            let start_slot = start_slot.parse::<Uint64>()
                .map_err(|e| Error::Undefined(e.to_string()))?;
            let end_slot = splits.next().ok_or(Error::Undefined("unconventional file name".to_string()))?;
            let end_slot = end_slot.parse::<Uint64>()
                .map_err(|e| Error::Undefined(e.to_string()))?;

            if slot_param >= start_slot && slot_param <= end_slot {
                // we found it! return this one
                log::info!("we found it! return {}", filename);
                return Ok(filename);
            }
        }

        Err(Error::Undefined(format!("Cannot find file for slot {}", slot_param)))
    }
}

impl FileHandler<HashMap<Hash, Slot>> for TxHashMap {
    fn write_to_file(value: Self) -> Result<String, Error> {

        let res = bincode::serialize(&value)
            .map_err(|e| Error::Undefined(e.to_string()))?;

        let mut path = PathBuf::new();
        path.push("./tx_hashes");
        path.push(value.0.clone());

        let mut file = File::create(path).map_err(|e| Error::Undefined(e.to_string()))?;
        file.write_all(&res).map_err(|e| Error::Undefined(e.to_string()))?;

        Ok(value.0)
    }

    fn read_file(filename: String) -> HashMap<Hash, Slot> {
        let mut m: HashMap<Hash,Slot> = HashMap::new();

        let mut path = PathBuf::new();
        path.push("./tx_hashes");
        path.push(filename);

        if let Ok(mut file) = File::open(path) {
            let mut bytes: Vec<u8> = vec![];
            let read_size = file.read_to_end(&mut bytes)
                .unwrap_or(0);

            if read_size > 0 {
                m = bincode::deserialize(&bytes)
                    .unwrap_or(HashMap::new());
            }
        }

        m
    }

    fn find_file_by_slot(slot_param: Slot) -> Result<String, Error> {
        let paths = fs::read_dir("./tx_hashes")
            .map_err(|e| Error::Undefined(e.to_string()))?;

        for path in paths {
            let filename = path.map_err(|e| Error::Undefined(e.to_string()))?
                .file_name().into_string().unwrap();
            let mut splits = filename.split("_");

            let start_slot = splits.next().ok_or(Error::Undefined("unconventional file name".to_string()))?;
            let start_slot = start_slot.parse::<Uint64>()
                .map_err(|e| Error::Undefined(e.to_string()))?;
            let end_slot = splits.next().ok_or(Error::Undefined("unconventional file name".to_string()))?;
            let end_slot = end_slot.parse::<Uint64>()
                .map_err(|e| Error::Undefined(e.to_string()))?;

            if slot_param >= start_slot && slot_param <= end_slot {
                // we found it! return this one
                log::info!("we found it! return {}", filename);
                return Ok(filename);
            }
        }

        Err(Error::Undefined(format!("Cannot find file for slot {}", slot_param)))


    }
}

pub struct ScpMessageCollector {
    start_slot:Slot,
    envelopes_map: EnvelopesMap,
    txset_map:TxSetMap,
    tx_hash_map: HashMap<Hash, Slot>,
    network:Network
}

impl ScpMessageCollector {
    
    pub fn new(network:Network) -> Self {
        ScpMessageCollector {
            start_slot: 0,
            envelopes_map: Default::default(),
            txset_map: Default::default(),
            tx_hash_map: Default::default(),
            network
        }
        
    }

    async fn handle_envelope(
        &mut self,
        env: ScpEnvelope,
        txset_hash_map: &mut TxSetCheckerMap,
        user: &UserControls
    ) -> Result<(), Box<dyn std::error::Error>> {
        let slot = env.statement.slot_index;

        if let ScpStatementPledges::ScpStExternalize(stmt) = &env.statement.pledges {
            // let's mark our starting slot
            if self.start_slot == 0 {
                log::info!("start slot: {}", slot);
                
                self.start_slot = slot;
            }

            let txset_hash = get_tx_set_hash(stmt)?;

            if let None = txset_hash_map.get(&txset_hash) {
                // let's check if whether this happened during insertion of txset.
                if !self.txset_map.contains_key(&slot) {
                    // we're creating a new entry
                    txset_hash_map.insert(txset_hash,slot);
                    user.send(StellarMessage::GetTxSet(txset_hash)).await?;

                    // check if we need to write to file
                    self.check_write_envelopes_to_file()?;
                }
            }

            // insert/add messages
            match self.envelopes_map.get_mut(&slot) {
                None => {
                    log::info!("slot: {} add to envelopes map", slot);

                    self.envelopes_map.insert(slot,vec![env]);
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

        // map is too small; we don't have to write it to file just yet.
        if keys.len() < usize::try_from(MAX_SLOTS_PER_FILE).unwrap_or(0) {
            return Ok(());
        }

        log::debug!("The map is getting big. Let's write to file:");
        // checker if we really have to write to file.
        let mut to_write = false;
       
        // indicates the first slot to be written to the NEXT file.
        let mut next_first_slot = self.start_slot;

        // only write a max of MAX_SLOTS_PER_FILE entries.
        let mut counter = 0; 
        
        while let Some(key) = keys.next() {
            // save to file if all data for the corresponding slots have been filled.
            if counter == MAX_SLOTS_PER_FILE {
                next_first_slot = *key; 
                to_write = true;
                break;
            }
            
            if let Some(value) = self.envelopes_map.get(key) {
                // check if we have enough externalized messages for the corresponding key
                if value.len() < MIN_EXTERNALIZED_MESSAGES {
                    log::info!("slot: {} not enough messages. Let's wait for more.", key);
                    break;
                }
            } else {
                // something wrong??? race condition?
                log::error!("slot: {} SOMETHING'S WRONG!", key);
                break;
            }
            
            counter+=1;
        }

        if to_write {
            self.write_envelopes_to_file(next_first_slot)?;
        }
        
        Ok(())
    }
    
    fn write_envelopes_to_file(&mut self, last_slot:Slot) -> Result<(), Box<dyn std::error::Error>> {
        let new_slot_map = self.envelopes_map.split_off(&last_slot);
        log::info!("saving old envelopes to file: {:?}", self.envelopes_map.keys());
        
        EnvelopesMap::write_to_file(self.envelopes_map.clone())?;
        self.envelopes_map = new_slot_map;
        self.start_slot = last_slot;
        log::info!("start slot is now: {:?}", self.start_slot);
        
        Ok(())
    }
    
    fn handle_tx_set(
        &mut self, 
        set: &TransactionSet,
        txset_hash_map: &mut TxSetCheckerMap) -> Result<(), Box<dyn std::error::Error>> {

        self.check_write_tx_set_to_file()?;

        // compute the tx_set_hash, to check what slot this set belongs too.
        let tx_set_hash = compute_non_generic_tx_set_content_hash(set);
        
        if let Some(slot) = txset_hash_map.remove(&tx_set_hash) {
            log::info!("slot: {} insert tx_set_hash", slot);
            self.txset_map.insert(slot,set.clone());
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

        log::info!("saving old transactions to file: {:?}", self.txset_map.keys());

        let file_name = TxSetMap::write_to_file(self.txset_map.clone())?;
        TxHashMap::write_to_file((file_name, self.tx_hash_map.clone()))?;

        self.txset_map = TxSetMap::new();
        self.tx_hash_map = HashMap::new();

        Ok(())
    }


    fn update_tx_hash_map(&mut self, slot:Slot, set:&TransactionSet) {
        set.txes.get_vec().iter().for_each(|tx_env| {
            let tx_hash = tx_env.get_hash(&self.network);
            self.tx_hash_map.insert(tx_hash,slot);
        });
    }
}

fn get_tx_set_hash(x:&ScpStatementExternalize) -> Result<Hash, stellar_relay::xdr_converter::Error> {
    let scp_value = x.commit.value.get_vec();
    parse_stellar_type!(scp_value, StellarValue)
       .map(|scp_value| scp_value.tx_set_hash )
}




#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let slot = 42784130;
    if let Ok(file) = EnvelopesMap::find_file_by_slot(slot) {
        println!("the filename:: {:?}", file);
        let result = EnvelopesMap::read_file(file);
        println!("\nenvelopesmap: {:?}", result.get(&slot));
    }

    if let Ok(file) = TxHashMap::find_file_by_slot(slot) {
        println!("\n\nthe filename: {:?}", file);

        let result = TxHashMap::read_file(file.clone());
        println!("\nhashmap: {:?}", result.keys());


        let result = TxSetMap::read_file(file.clone());
        println!("\ntxset: {:?}", result.get(&slot));
    }

    Ok(())
}



/*
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
    
    loop {
        if let Some(conn_state) = user.recv().await {
            match conn_state {
                StellarNodeMessage::Data { p_id, msg_type, msg } => match msg {
                   StellarMessage::ScpMessage(env) => {
                       collector.handle_envelope(env,&mut tx_set_hash_map,&user).await?;
                   }
                    StellarMessage::TxSet(set) => {
                        collector.handle_tx_set(&set, &mut tx_set_hash_map)?;
                    }
                    _ => {
                        
                    }
                }
                    
                _ => {}
            }
        }
    }

}

*/