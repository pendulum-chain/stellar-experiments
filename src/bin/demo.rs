#![allow(dead_code)]

use std::{
    collections::{btree_map::Keys, BTreeMap, HashMap},
    convert::{TryFrom, TryInto},
    fs,
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    str::Split,
};
use substrate_stellar_sdk::{
    types::{PaymentOp, Transaction, TransactionEnvelope, TransactionV0},
    Asset, SecretKey,
};

use stellar_relay::{
    connect, helper::compute_non_generic_tx_set_content_hash, node::NodeInfo, ConnConfig, Error,
    StellarNodeMessage, UserControls,
};

use stellar_relay::sdk::{
    compound_types::UnlimitedVarArray,
    network::Network,
    types::{
        ScpEnvelope, ScpStatementExternalize, ScpStatementPledges, StellarMessage, TransactionSet,
        Uint64,
    },
    Hash, XdrCodec,
};

pub type Slot = Uint64;
pub type TxSetHash = Hash;
pub type TxHash = Hash;
pub type SerializedData = Vec<u8>;
pub type Filename = String;

/// For easy writing to file. BTreeMap to preserve order of the slots.
pub type SlotEncodedMap = BTreeMap<Slot, SerializedData>;

/// The slot is not found in the `StellarMessage::TxSet(...)`, therefore this map
/// serves as a holder of the slot when we hash the txset.
pub type TxSetCheckerMap = HashMap<TxSetHash, Slot>;

/// Todo: these maps should be merged into one; but there was a complication (which differs in every run):
/// Sometimes not enough `StellarMessage::ScpMessage(...)` are sent per slot;
/// or that the `Stellar:message::TxSet(...)` took too long to arrive (may not even arrive at all)
/// So I've kept both of them separate.
#[derive(Clone, Debug)]
pub struct EnvelopesMap(BTreeMap<Slot, Vec<ScpEnvelope>>);

#[derive(Clone, Debug)]
pub struct TxSetMap(BTreeMap<Slot, TransactionSet>);

pub type TxHashMap<'a> = (String, &'a HashMap<TxHash, Slot>);

/// This is for `EnvelopesMap`; how many slots is accommodated per file.
pub const MAX_SLOTS_PER_FILE: Uint64 = 15;

/// This is for `EnvelopesMap`. Make sure that we have a minimum set of envelopes per slot,
/// before writing to file.
pub const MIN_EXTERNALIZED_MESSAGES: usize = 15;

/// This is both for `TxSetMap` and `TxHashMap`.
/// When the map reaches the MAX or more, then we write to file.
pub const MAX_TXS_PER_FILE: Uint64 = 5000;

impl EnvelopesMap {
    fn new() -> Self {
        let inner: BTreeMap<Slot, Vec<ScpEnvelope>> = BTreeMap::new();
        EnvelopesMap(inner)
    }

    fn insert(&mut self, key: Slot, value: Vec<ScpEnvelope>) -> Option<Vec<ScpEnvelope>> {
        self.0.insert(key, value)
    }

    fn keys(&self) -> Keys<'_, Slot, Vec<ScpEnvelope>> {
        self.0.keys()
    }

    fn get(&self, key: &Slot) -> Option<&Vec<ScpEnvelope>> {
        self.0.get(key)
    }

    fn get_mut(&mut self, key: &Slot) -> Option<&mut Vec<ScpEnvelope>> {
        self.0.get_mut(key)
    }

    fn split_off(&mut self, key: &Slot) -> Self {
        EnvelopesMap(self.0.split_off(key))
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

impl Default for EnvelopesMap {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl TxSetMap {
    fn new() -> Self {
        TxSetMap(BTreeMap::new())
    }

    fn contains_key(&self, key: &Slot) -> bool {
        self.0.contains_key(key)
    }

    fn insert(&mut self, key: Slot, value: TransactionSet) -> Option<TransactionSet> {
        self.0.insert(key, value)
    }

    fn keys(&self) -> Keys<'_, Slot, TransactionSet> {
        self.0.keys()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

impl Default for TxSetMap {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

pub trait FileHandler<T: Default> {
    // path to where the file should be saved
    const PATH: &'static str;

    fn create_filename_and_data(&self) -> Result<(Filename, SerializedData), Error>;

    fn deserialize_bytes(bytes: Vec<u8>) -> Result<T, Error>;

    fn check_slot_in_splitted_filename(slot_param: Slot, splits: &mut Split<&str>) -> bool;

    fn get_path(filename: &str) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(Self::PATH);
        path.push(filename);
        path
    }

    fn write_to_file(&self) -> Result<Filename, Error> {
        let (filename, data) = self.create_filename_and_data()?;

        let path = Self::get_path(&filename);
        let mut file = File::create(path)?;

        file.write_all(&data)?;

        Ok(filename)
    }

    fn read_file(filename: &str) -> Result<T, Error> {
        let path = Self::get_path(filename);
        let mut file = File::open(path)?;

        let mut bytes: Vec<u8> = vec![];
        let read_size = file.read_to_end(&mut bytes)?;

        if read_size > 0 {
            return Self::deserialize_bytes(bytes);
        }

        Ok(T::default())
    }

    fn find_file_by_slot(slot_param: Slot) -> Result<String, Error> {
        let paths = fs::read_dir(Self::PATH)?;

        for path in paths {
            let filename_with_ext = path?.file_name().into_string().unwrap();
            let filename = filename_with_ext.replace(".json", "");
            let mut splits = filename.split("_");

            if Self::check_slot_in_splitted_filename(slot_param, &mut splits) {
                return Ok(filename_with_ext);
            }
        }

        Err(Error::Other(format!(
            "Cannot find file for slot {}",
            slot_param
        )))
    }
}

impl FileHandler<Self> for EnvelopesMap {
    const PATH: &'static str = "./scp_envelopes";

    fn create_filename_and_data(&self) -> Result<(Filename, SerializedData), Error> {
        let mut filename: Filename = "".to_string();
        let mut m: SlotEncodedMap = SlotEncodedMap::new();
        let len = self.0.len();

        for (idx, (key, value)) in self.0.iter().enumerate() {
            if idx == 0 {
                filename.push_str(&format!("{}_", key));
            }

            if idx == (len - 1) {
                filename.push_str(&format!("{}.json", key));
            }

            let stellar_array = UnlimitedVarArray::new(value.clone())?; //.map_err(Error::from)?;
            m.insert(*key, stellar_array.to_xdr());
        }

        let res = bincode::serialize(&m)?;

        Ok((filename, res))
    }

    fn deserialize_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        let inside: SlotEncodedMap = bincode::deserialize(&bytes)?;

        let mut m: EnvelopesMap = EnvelopesMap::new();
        for (key, value) in inside.into_iter() {
            if let Ok(envelopes) = UnlimitedVarArray::<ScpEnvelope>::from_xdr(value) {
                m.insert(key, envelopes.get_vec().to_vec());
            }
        }

        Ok(m)
    }

    fn check_slot_in_splitted_filename(slot_param: Slot, splits: &mut Split<&str>) -> bool {
        fn parse_slot(slot_opt: Option<&str>) -> Option<Slot> {
            (slot_opt?).parse::<Slot>().ok()
        }

        if let Some(start_slot) = parse_slot(splits.next()) {
            if let Some(end_slot) = parse_slot(splits.next()) {
                return (slot_param >= start_slot) && (slot_param <= end_slot);
            }
        }

        false
    }
}

impl FileHandler<Self> for TxSetMap {
    const PATH: &'static str = "./tx_sets";

    fn create_filename_and_data(&self) -> Result<(Filename, SerializedData), Error> {
        let mut filename: Filename = "".to_string();
        let mut m: SlotEncodedMap = SlotEncodedMap::new();
        let len = self.0.len();

        for (idx, (key, set)) in self.0.iter().enumerate() {
            if idx == 0 {
                filename.push_str(&format!("{}_", key));
            }

            if idx == (len - 1) {
                filename.push_str(&format!("{}.json", key));
            }

            m.insert(*key, set.to_xdr());
        }

        Ok((filename, bincode::serialize(&m)?))
    }

    fn deserialize_bytes(bytes: Vec<u8>) -> Result<TxSetMap, Error> {
        let inside: SlotEncodedMap = bincode::deserialize(&bytes)?;

        let mut m: TxSetMap = TxSetMap::new();

        for (key, value) in inside.into_iter() {
            if let Ok(set) = TransactionSet::from_xdr(value) {
                m.insert(key, set);
            }
        }

        Ok(m)
    }

    fn check_slot_in_splitted_filename(slot_param: Slot, splits: &mut Split<&str>) -> bool {
        EnvelopesMap::check_slot_in_splitted_filename(slot_param, splits)
    }
}

impl<'a> FileHandler<HashMap<Hash, Slot>> for TxHashMap<'a> {
    const PATH: &'static str = "./tx_hashes";

    fn create_filename_and_data(&self) -> Result<(Filename, SerializedData), Error> {
        Ok((self.0.clone(), bincode::serialize(&self.1)?))
    }

    fn deserialize_bytes(bytes: Vec<u8>) -> Result<HashMap<Hash, Slot>, Error> {
        bincode::deserialize(&bytes).map_err(Error::from)
    }

    fn check_slot_in_splitted_filename(slot_param: Slot, splits: &mut Split<&str>) -> bool {
        TxSetMap::check_slot_in_splitted_filename(slot_param, splits)
    }
}

pub struct ScpMessageCollector {
    /// holds the mapping of the Slot Number(key) and the ScpEnvelopes(value)
    envelopes_map: EnvelopesMap,
    /// holds the mapping of the Slot Number(key) and the TransactionSet(value)
    txset_map: TxSetMap,
    /// holds the mapping of the Transaction Hash(key) and the Slot Number(value)
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

    /// handles incoming ScpEnvelope.
    ///
    /// # Arguments
    ///
    /// * `env` - the ScpEnvelope
    /// * `txset_hash_map` - provides the slot number of the given Transaction Set Hash
    /// * `user` - The UserControl used for sending messages to Stellar Node
    async fn handle_envelope(
        &mut self,
        env: ScpEnvelope,
        txset_hash_map: &mut TxSetCheckerMap,
        user: &UserControls,
    ) -> Result<(), Error> {
        let slot = env.statement.slot_index;

        // we are only interested with `ScpStExternalize`. Other messages are ignored.
        if let ScpStatementPledges::ScpStExternalize(stmt) = &env.statement.pledges {
            let txset_hash = get_tx_set_hash(stmt)?;

            if txset_hash_map.get(&txset_hash).is_none() &&
                // let's check whether this is a delayed message.
                !self.txset_map.contains_key(&slot)
            {
                // we're creating a new entry
                txset_hash_map.insert(txset_hash, slot);
                user.send(StellarMessage::GetTxSet(txset_hash)).await?;

                // check if we need to write to file
                self.check_write_envelopes_to_file()?;
            }

            // insert/add messages
            match self.envelopes_map.get_mut(&slot) {
                None => {
                    log::info!("slot: {} add to envelopes map", slot);

                    self.envelopes_map.insert(slot, vec![env]);
                }
                Some(value) => {
                    value.push(env);
                }
            }
        }

        Ok(())
    }

    /// checks whether the envelopes map requires saving to file.
    fn check_write_envelopes_to_file(&mut self) -> Result<(), Error> {
        let mut keys = self.envelopes_map.keys();
        let keys_len = u64::try_from(keys.len()).unwrap_or(0);

        // map is too small; we don't have to write it to file just yet.
        if keys_len < MAX_SLOTS_PER_FILE {
            return Ok(());
        }

        log::info!("The map is getting big. Let's write to file:");

        let mut counter = 0;
        while let Some(key) = keys.next() {
            // save to file if all data for the corresponding slots have been filled.
            if counter == MAX_SLOTS_PER_FILE {
                self.write_envelopes_to_file(*key)?;
                break;
            }

            if let Some(value) = self.envelopes_map.get(key) {
                // check if we have enough externalized messages for the corresponding key
                if value.len() < MIN_EXTERNALIZED_MESSAGES && keys_len < MAX_SLOTS_PER_FILE * 5 {
                    log::info!("slot: {} not enough messages. Let's wait for more.", key);
                    break;
                }
            } else {
                // something wrong??? race condition?
                break;
            }

            counter += 1;
        }

        Ok(())
    }

    fn write_envelopes_to_file(&mut self, last_slot: Slot) -> Result<(), Error> {
        let new_slot_map = self.envelopes_map.split_off(&last_slot);
        self.envelopes_map.write_to_file()?;
        self.envelopes_map = new_slot_map;
        log::info!("start slot is now: {:?}", last_slot);

        Ok(())
    }

    /// handles incoming TransactionSet.
    ///
    /// # Arguments
    ///
    /// * `set` - the TransactionSet
    /// * `txset_hash_map` - provides the slot number of the given Transaction Set Hash
    fn handle_tx_set(
        &mut self,
        set: &TransactionSet,
        txset_hash_map: &mut TxSetCheckerMap,
    ) -> Result<(), Error> {
        self.check_write_tx_set_to_file()?;

        // compute the tx_set_hash, to check what slot this set belongs too.
        let tx_set_hash = compute_non_generic_tx_set_content_hash(set);

        if let Some(slot) = txset_hash_map.remove(&tx_set_hash) {
            self.txset_map.insert(slot, set.clone());
            self.update_tx_hash_map(slot, set);
        } else {
            log::info!("WARNING! tx_set_hash: {:?} has no slot.", tx_set_hash);
        }

        Ok(())
    }

    /// checks whether the transaction set map requires saving to file.
    fn check_write_tx_set_to_file(&mut self) -> Result<(), Error> {
        // map is too small; we don't have to write it to file just yet.
        if self.tx_hash_map.len() < usize::try_from(MAX_TXS_PER_FILE).unwrap_or(0) {
            return Ok(());
        }

        log::info!(
            "saving old transactions to file: {:?}",
            self.txset_map.keys()
        );

        let filename = self.txset_map.write_to_file()?;

        (filename, &self.tx_hash_map).write_to_file()?;

        self.txset_map = TxSetMap::new();
        self.tx_hash_map = HashMap::new();

        Ok(())
    }

    /// maps the slot to the transactions of the TransactionSet
    fn update_tx_hash_map(&mut self, slot: Slot, set: &TransactionSet) {
        log::info!("slot: {} inserting transacion set", slot);
        set.txes.get_vec().iter().for_each(|tx_env| {
            let tx_hash = tx_env.get_hash(&self.network);

            match tx_env {
                TransactionEnvelope::EnvelopeTypeTxV0(value) => {
                    print_new_transaction_v0(value.tx.clone())
                }
                TransactionEnvelope::EnvelopeTypeTx(value) => {
                    print_new_transaction(value.tx.clone())
                }
                TransactionEnvelope::EnvelopeTypeTxFeeBump(_) => {
                    log::info!("EnvelopeTypeTxFeeBump")
                }
                TransactionEnvelope::Default(code) => log::info!("Default: {:?}", code),
            }
            self.tx_hash_map.insert(tx_hash, slot);
        });
    }
}

fn print_new_transaction_v0(transaction: TransactionV0) {
    log::info!("--- Processing new v0 transaction ---");
    let source = substrate_stellar_sdk::PublicKey::from_binary(transaction.source_account_ed25519);

    let payment_ops: Vec<&PaymentOp> = transaction
        .operations
        .get_vec()
        .into_iter()
        .filter_map(|op| match &op.body {
            substrate_stellar_sdk::types::OperationBody::Payment(p) => Some(p),
            _ => None,
        })
        .collect();

    if payment_ops.len() == 0 {
        log::info!("Transaction doesn't include payments");
    } else {
        for payment_op in payment_ops {
            let amount = payment_op.amount;
            let asset = payment_op.asset.clone();
            log::info!("{:?}", amount);
            log::info!("{:?}", asset);
            log::info!("{:?}", source);
        }
    }
    log::info!("--- Finish new v0 transaction ---");
}

fn print_new_transaction(transaction: Transaction) {
    log::info!("--- Processing new transaction ---");
    let source = if let substrate_stellar_sdk::MuxedAccount::KeyTypeEd25519(key) =
        transaction.source_account
    {
        log::info!(
            "Source account {:#?}",
            std::str::from_utf8(
                substrate_stellar_sdk::PublicKey::from_binary(key)
                    .to_encoding()
                    .as_slice()
            )
            .unwrap()
        )
    } else {
        log::error!("❌  Pub key couldn't be decoded");
        return;
    };

    let payment_ops: Vec<&PaymentOp> = transaction
        .operations
        .get_vec()
        .into_iter()
        .filter_map(|op| match &op.body {
            substrate_stellar_sdk::types::OperationBody::Payment(p) => Some(p),
            _ => None,
        })
        .collect();

    if payment_ops.len() == 0 {
        log::info!("Transaction doesn't include payments");
    } else {
        for payment_op in payment_ops {
            let amount = payment_op.amount;
            let asset = payment_op.asset.clone();
            log::info!("{:?}", amount);
            print_asset(asset);
            log::info!("{:?}", source);
        }
    }
    log::info!("--- Finish new transaction ---");
}

fn print_asset(asset: Asset) {
    match asset {
        Asset::AssetTypeNative => log::info!("XLM"),
        Asset::AssetTypeCreditAlphanum4(value) => {
            log::info!(
                "{:?}",
                std::str::from_utf8(value.asset_code.as_slice()).unwrap()
            );
            log::info!(
                "{:?}",
                std::str::from_utf8(value.issuer.to_encoding().as_slice()).unwrap()
            );
        }
        Asset::AssetTypeCreditAlphanum12(value) => {
            log::info!(
                "{:?}",
                std::str::from_utf8(value.asset_code.as_slice()).unwrap()
            );
            log::info!(
                "{:?}",
                std::str::from_utf8(value.issuer.to_encoding().as_slice()).unwrap()
            );
        }
        Asset::Default(code) => log::info!("Asset type {:?}", code),
    }
}

fn get_tx_set_hash(x: &ScpStatementExternalize) -> Result<Hash, Error> {
    let scp_value = x.commit.value.get_vec();
    scp_value[0..32].try_into().map_err(Error::from)
}

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
                    log::info!("---- PID: {} Handle {:?}----", p_id, msg_type);
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
mod test {
    use crate::{get_tx_set_hash, EnvelopesMap, FileHandler, TxHashMap, TxSetMap};
    use stellar_relay::helper::compute_non_generic_tx_set_content_hash;
    use stellar_relay::sdk::types::ScpStatementPledges;
    use substrate_stellar_sdk::network::Network;

    #[test]
    fn find_file_successful() {
        let slot = 42867089;

        let file_name = EnvelopesMap::find_file_by_slot(slot).expect("should return a file");
        assert_eq!(&file_name, "42867088_42867102.json");

        let file_name = TxSetMap::find_file_by_slot(slot).expect("should return a file");
        assert_eq!(&file_name, "42867088_42867102.json");

        let file_name = TxHashMap::find_file_by_slot(slot).expect("should return a file");
        assert_eq!(&file_name, "42867088_42867102.json");

        let slot = 42867150;

        let file_name = EnvelopesMap::find_file_by_slot(slot).expect("should return a file");
        assert_eq!(&file_name, "4286148_42867162.json");

        let file_name = TxSetMap::find_file_by_slot(slot).expect("should return a file");
        assert_eq!(&file_name, "42867135_42867150.json");

        let file_name = TxHashMap::find_file_by_slot(slot).expect("should return a file");
        assert_eq!(&file_name, "42867135_42867150.json");
    }

    #[test]
    fn read_file_successful() {
        let first_slot = 42867118;
        let last_slot = 42867132;

        let envelopes_map = EnvelopesMap::read_file(&format!("{}_{}.json", first_slot, last_slot))
            .expect("should return a map");

        for (idx, slot) in envelopes_map.keys().enumerate() {
            let expected_slot_num =
                first_slot + u64::try_from(idx).expect("should return u64 data type");
            assert_eq!(slot, &expected_slot_num);
        }

        let scp_envelopes = envelopes_map
            .get(&last_slot)
            .expect("should have scp envelopes");

        for x in scp_envelopes {
            assert_eq!(x.statement.slot_index, last_slot);
        }

        let filename = TxSetMap::find_file_by_slot(last_slot).expect("should return a filename");
        let txset_map = TxSetMap::read_file(&filename).expect("should return a txset map");

        let txset = txset_map.0.get(&last_slot).expect("should have a txset");
        let tx_set_hash = compute_non_generic_tx_set_content_hash(txset);

        let first = scp_envelopes.first().expect("should return an envelope");

        if let ScpStatementPledges::ScpStExternalize(stmt) = &first.statement.pledges {
            let expected_tx_set_hash = get_tx_set_hash(stmt).expect("return a tx set hash");

            assert_eq!(tx_set_hash, expected_tx_set_hash);
        } else {
            assert!(false);
        }

        let txes = txset.txes.get_vec();
        let idx = txes.len() / 2;
        let tx = txes.get(idx).expect("should return a tx envelope.");

        let network = Network::new(b"Public Global Stellar Network ; September 2015");

        let hash = tx.get_hash(&network);
        let txhash_map = TxHashMap::read_file(&filename).expect("should return txhash map");
        let actual_slot = txhash_map.get(&hash).expect("should return a slot number");
        assert_eq!(actual_slot, &last_slot);
    }
}
