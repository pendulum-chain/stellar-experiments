use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Bound::{Included,Excluded};
use std::fmt::format;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use stellar_relay::helper::{compute_non_generic_tx_set_content_hash, time_now};
use stellar_relay::node::NodeInfo;
use substrate_stellar_sdk::compound_types::UnlimitedVarArray;
use substrate_stellar_sdk::network::Network;
use substrate_stellar_sdk::types::OfferEntryFlags::PassiveFlag;
use substrate_stellar_sdk::types::{
    LedgerHeader, ScpStatementExternalize, ScpStatementPledges, TransactionSet, Uint256, Uint64,
};
use substrate_stellar_sdk::types::{ScpEnvelope, StellarMessage};
use substrate_stellar_sdk::{
    Hash, ReadStream, SecretKey, StellarSdkError, TransactionEnvelope, WriteStream, XdrCodec,
};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use stellar_relay::xdr_converter::log_decode_error;
use stellar_relay::{
    connect, parse_stellar_type, ConnConfig, Error, StellarNodeMessage, UserControls,
};

fn hash_str(hash: &[u8]) -> String {
    base64::encode(hash)
}

pub const MAX_SLOTS_PER_FILE: Uint64 = 5;
pub const MIN_EXTERNALIZED_MESSAGES: usize = 10;


#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExternalizedMessage {
    time: Uint64,
    tx_set: Option<TransactionSet>,
    envelopes: UnlimitedVarArray<ScpEnvelope>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, PartialOrd, Ord)]
pub struct XdrExternalizedMessage {
    time: Uint64,
    tx_set: String,
    envelopes: String,
}

impl ExternalizedMessage {
    pub fn new() -> Self {
        ExternalizedMessage {
            time: time_now(),
            tx_set: None,
            envelopes: UnlimitedVarArray::new_empty(),
        }
    }

    pub fn add_envelope(&mut self, value: ScpEnvelope) -> Result<(), Error> {
        self.envelopes.push(value).map_err(Error::from)
    }

    pub fn insert_tx_set(&mut self, tx_set: TransactionSet) {
        self.tx_set = Some(tx_set);
    }

    pub fn encode(&self) -> Vec<u8> {
        let tx_set = self.tx_set.to_xdr();
        let envelopes = self.envelopes.to_xdr();

        let xdr_struct = XdrExternalizedMessage {
            time: self.time,
            tx_set: base64::encode(&tx_set),
            envelopes: base64::encode(&envelopes),
        };

        serde_json::to_vec(&xdr_struct).unwrap()
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, Error> {
        let xdr_struct: XdrExternalizedMessage = serde_json::from_slice(encoded).unwrap();

        let tx_set = base64::decode_config(xdr_struct.tx_set, base64::STANDARD).unwrap();
        let tx_set = Option::<TransactionSet>::from_xdr(tx_set)
            .map_err(|e| log_decode_error("Option TransactionSet", e))?;

        let envelopes = base64::decode_config(xdr_struct.envelopes, base64::STANDARD).unwrap();
        let envelopes = UnlimitedVarArray::<ScpEnvelope>::from_xdr(envelopes)
            .map_err(|e| log_decode_error("LimitedVarArray ScpEnvelope", e))?;

        Ok(ExternalizedMessage {
            time: xdr_struct.time,
            tx_set,
            envelopes,
        })
    }
}

async fn write_map_to_file(
    x: BTreeMap<Uint64, ExternalizedMessage>,
) -> Result<(), Box<dyn std::error::Error>> {
    let len = x.len();

    // let's write this to file.

    let mut filename: String = "".to_string();
    let mut file: File;

    let mut m: BTreeMap<Uint64, Vec<u8>> = BTreeMap::new();

    for (idx, (key, value)) in x.into_iter().enumerate() {
        if idx == 0 {
            filename.push_str(&format!("{}_{}.json", key, time_now()));
        }

        m.insert(key, value.encode());
    }

    let res = serde_json::to_vec(&m)?;

    let mut path = PathBuf::new();
    path.push("./externalized_messages/");
    path.push(filename);
    file = File::create(path).await?;

    file.write_all(&res).await?;

    Ok(())
}

fn find_file_based_on_slot(wanted_slot: Uint64) -> Option<String> {
    let paths = fs::read_dir("./externalized_messages").unwrap();

    for path in paths {
        let file_name = path.unwrap().file_name().into_string().unwrap();
        let mut splits = file_name.split("_");

        if let Some(slot) = splits.next() {
            println!("THE SLOT? {}", slot);
            let slot_num = slot.parse::<Uint64>().unwrap();
            if wanted_slot >= slot_num || wanted_slot <= slot_num + MAX_SLOTS_PER_FILE {
                // we found it! return this one
                println!("we found it! return {}", file_name);
                return Some(file_name);
            }
        }
    }
    None
}

async fn read_file(
    file_name: &str,
) -> Result<BTreeMap<Uint64, ExternalizedMessage>, Box<dyn std::error::Error>> {
    let mut m: BTreeMap<Uint64, ExternalizedMessage> = BTreeMap::new();

    let mut path = PathBuf::new();
    path.push("./externalized_messages/");
    path.push(file_name);
    let mut file = File::open(path).await?;

    let mut bytes: Vec<u8> = vec![];
    let read_size = file.read_to_end(&mut bytes).await?;
    println!("read size: {:?}", read_size);

    if read_size > 0 {
        let inside: BTreeMap<Uint64, Vec<u8>> = serde_json::from_slice(&bytes)?;
        for (key, value) in inside.into_iter() {
            let result = ExternalizedMessage::decode(&value)?;
            m.insert(key, result);
        }
    }

    Ok(m)
}


fn get_tx_set_hash(x:&ScpStatementExternalize) -> Result<Hash,Error> {
    let scp_value = x.commit.value.get_vec();
    let scp_value = parse_stellar_type!(scp_value, StellarValue)?;
    Ok(scp_value.tx_set_hash)
}

/*
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(file) = find_file_based_on_slot(42780406) {
        let result = read_file(&file).await?;

        println!("the result: {:?}", result);
    }

    Ok(())
}
*/




#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    fs::create_dir_all("./externalized_messages")?;

    let network = Network::new(b"Public Global Stellar Network ; September 2015");

    let secret =
        SecretKey::from_encoding("SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73")
            .unwrap();

    let node_info = NodeInfo::new(19, 21, 19, "v19.1.0".to_string(), &network);

    let cfg = ConnConfig::new("135.181.16.110", 11625, secret, 0, false, true, false);

    let mut user: UserControls = connect(node_info, cfg).await?;

    // just a temporary holder
    let mut tx_set_hash_map: HashMap<Hash, Uint64> = HashMap::new();
    let mut first_slot = 0;


    // final maps
    // todo: if there is no issue/redeem request,then we don't have to store it.
    // for now, just store everything
    let mut slot_hash_map: BTreeMap<Uint64, ExternalizedMessage> = BTreeMap::new();
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

                                if slot == 0 {
                                    // let's mark the first_slot
                                    first_slot = slot;
                                }

                                let tx_hash = get_tx_set_hash(x)?;

                                // println!("\npid: {:?} let's see: slot {:?} node_id {:?}, tx_set_hash: {:?}, quorum_set_hash: {:?}",
                                //          p_id, slot,
                                //          env.statement.node_id, hash_str(&tx_hash),
                                //          hash_str(&x.commit_quorum_set_hash)
                                // );

                                // we're creating a new entry
                                if let None = tx_set_hash_map.get(&tx_hash) {
                                    println!("creating new entry for slot {}", slot);
                                    tx_set_hash_map.insert(tx_hash, slot);
                                    user.send(StellarMessage::GetTxSet(tx_hash)).await?;

                                    let mut to_write = false;
                                    let mut last_slot = first_slot;

                                    let mut keys = slot_hash_map.keys();
                                    println!("keys len: {}", keys.len());
                                    if keys.len() >= usize::try_from(MAX_SLOTS_PER_FILE).unwrap() {
                                        // let's check whether everything that needs to be stored, has been filled.

                                        let mut counter = 0;
                                        while let Some(key) = keys.next() {
                                            // save to file if all data for the corresponding slots have been filled.
                                            if counter == MAX_SLOTS_PER_FILE {
                                                println!("now let's save to file");
                                                last_slot = *key;
                                                to_write = true;
                                                break;
                                            }

                                            if let Some(value) = slot_hash_map.get(key) {
                                                // check if we have enough externalized messages for the corresponding key
                                                if value.envelopes.len() < MIN_EXTERNALIZED_MESSAGES {
                                                    println!("slot {} does not have enough messages.", key);
                                                    break;
                                                }

                                                // check if tx_set has been filled.
                                                if value.tx_set.is_none() {
                                                    println!("slot {} does not have a tx_set yet. Let's ask for it again.", key);
                                                    let res = value.envelopes.get_vec().first().unwrap();
                                                    if let ScpStatementPledges::ScpStExternalize(res) = &res.statement.pledges {
                                                        let tx_hash = get_tx_set_hash(res)?;
                                                        user.send(StellarMessage::GetTxSet(tx_hash)).await?;
                                                    }

                                                    break;
                                                }
                                            } else {
                                                println!("error!!!!!!! slot {} does not exist", key);
                                                break;
                                                // something wrong
                                            }

                                            counter+=1;
                                        }
                                    }

                                    if to_write {
                                        let new_slot_map = slot_hash_map.split_off(&last_slot);
                                        println!("saving to file: {:?}", slot_hash_map.keys());
                                        write_map_to_file(slot_hash_map.clone()).await?;
                                        slot_hash_map = new_slot_map;
                                        first_slot = last_slot;
                                        println!("first slot is now: {:?}", first_slot);
                                    }

                                }

                                if let Some(value) = slot_hash_map.get_mut(&slot) {
                                   // println!("adding message to slot {:?} of existing value", slot);
                                    value.add_envelope(env.clone())?
                                } else {
                                   // println!("adding message to slot {:?}. no existing value.", slot);
                                    let mut msg = ExternalizedMessage::new();
                                    msg.add_envelope(env.clone())?;
                                    slot_hash_map.insert(slot, msg);
                                }
                            }
                            _ => {
                                //println!("\n pid: {:?} continue...", p_id);
                            }
                        },
                        StellarMessage::TxSet(set) => {
                            // println!("The set: {:?} prev_ledger_hash: {:?}", set.txes.len(), set.previous_ledger_hash);

                            let tx_set_hash = compute_non_generic_tx_set_content_hash(&set);

                            if let Some(slot) = tx_set_hash_map.get(&tx_set_hash) {
                                let _ = slot_hash_map.entry(*slot).and_modify(|value| {
                                    (*value).insert_tx_set(set.clone());
                                    println!("inserting tx set to slot: {}", slot);
                                });

                               //  println!("\npid: {:?} This tx set:: {:?} belongs to slot {} with size: {:?}", p_id, hash_str(&tx_set_hash), slot, set.txes.len());

                                set.txes.get_vec().iter().for_each(|tx_env| {
                                    let tx_hash = tx_env.get_hash(&network);
                                    tx_hash_map.insert(tx_hash, slot.clone());
                                });


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
                            //println!("\n pid: {:?} continue...", p_id);
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
