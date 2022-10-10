#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::vec;

use sp_keyring::AccountKeyring;
use substrate_stellar_sdk::{Asset, SecretKey, Transaction};
use substrate_stellar_sdk::compound_types::UnlimitedVarArray;
use substrate_stellar_sdk::network::{Network, PUBLIC_NETWORK, TEST_NETWORK};
use substrate_stellar_sdk::TransactionEnvelope;
use substrate_stellar_sdk::types::{
    PaymentOp, ScpEnvelope, StellarMessage, TransactionSet, Uint64,
};
use subxt::{OnlineClient, PolkadotConfig, tx::PairSigner};

use collector::*;
use constants::*;
use error::Error;
use handler::*;
use stellar_relay::{ConnConfig, connect, node::NodeInfo, StellarNodeMessage, UserControls};
use traits::*;
use types::*;

mod error {
    use std::array::TryFromSliceError;

    use substrate_stellar_sdk::StellarSdkError;

    #[derive(Debug, err_derive::Error)]
    pub enum Error {
        #[error(display = "{:?}", _0)]
        StellarSdkError(StellarSdkError),

        #[error(display = "{:?}", _0)]
        TryFromSliceError(TryFromSliceError),

        #[error(display = "{:?}", _0)]
        SerdeError(bincode::Error),

        #[error(display = "{:?}", _0)]
        StdIoError(std::io::Error),

        #[error(display = "{:?}", _0)]
        Other(String),

        #[error(display = "{:?}", _0)]
        ConnError(stellar_relay::ConnectionError),

        #[error(display = "{:?}", _0)]
        SubExtError(subxt::Error),
    }

    impl From<StellarSdkError> for Error {
        fn from(e: StellarSdkError) -> Self {
            Error::StellarSdkError(e)
        }
    }

    impl From<std::io::Error> for Error {
        fn from(e: std::io::Error) -> Self {
            Error::StdIoError(e)
        }
    }

    impl From<bincode::Error> for Error {
        fn from(e: bincode::Error) -> Self {
            Error::SerdeError(e)
        }
    }

    impl From<TryFromSliceError> for Error {
        fn from(e: TryFromSliceError) -> Self {
            Error::TryFromSliceError(e)
        }
    }

    impl From<stellar_relay::ConnectionError> for Error {
        fn from(e: stellar_relay::ConnectionError) -> Self {
            Error::ConnError(e)
        }
    }

    impl From<subxt::Error> for Error {
        fn from(e: subxt::Error) -> Self {
            Error::SubExtError(e)
        }
    }
}

mod types {
    use substrate_stellar_sdk::types::{Hash, ScpEnvelope};

    use super::*;

    pub type Slot = Uint64;
    pub type TxHash = Hash;
    pub type TxSetHash = Hash;
    pub type Filename = String;

    pub type SerializedData = Vec<u8>;

    /// For easy writing to file. BTreeMap to preserve order of the slots.
    pub(crate) type SlotEncodedMap = BTreeMap<Slot, SerializedData>;

    /// Sometimes not enough `StellarMessage::ScpMessage(...)` are sent per slot;
    /// or that the `Stellar:message::TxSet(...)` took too long to arrive (may not even arrive at all)
    /// So I've kept both of them separate: the `EnvelopesMap` and the `TxSetMap`
    pub type EnvelopesMap = BTreeMap<Slot, Vec<ScpEnvelope>>;
    pub type TxSetMap = BTreeMap<Slot, TransactionSet>;

    pub type TxHashMap = HashMap<TxHash, Slot>;

    /// The slot is not found in the `StellarMessage::TxSet(...)`, therefore this map
    /// serves as a holder of the slot when we hash the txset.
    pub type TxSetCheckerMap = HashMap<TxSetHash, Slot>;
}

mod constants {
    use super::*;

    /// This is for `EnvelopesMap`; how many slots is accommodated per file.
    pub const MAX_SLOTS_PER_FILE: Slot = 200;

    /// This is for `EnvelopesMap`. Make sure that we have a minimum set of envelopes per slot,
    /// before writing to file.
    pub const MIN_EXTERNALIZED_MESSAGES: usize = 15;

    /// This is both for `TxSetMap` and `TxHashMap`.
    /// When the map reaches the MAX or more, then we write to file.
    pub const MAX_TXS_PER_FILE: Uint64 = 10_000_000;

    pub const VAULT_ADDRESSES_FILTER: &[&str] =
        &["GAP4SFKVFVKENJ7B7VORAYKPB3CJIAJ2LMKDJ22ZFHIAIVYQOR6W3CXF"];

    pub const TIER_1_VALIDATOR_IP_TESTNET: &str = "34.235.168.98";
    pub const TIER_1_VALIDATOR_IP_PUBLIC: &str = "135.181.16.110";
}

mod traits {
    use std::fs;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::str::Split;

    use super::*;

    pub trait FileHandlerExt<T: Default>: FileHandler<T> {
        fn create_filename_and_data(data: &T) -> Result<(Filename, SerializedData), Error>;

        fn write_to_file(data: &T) -> Result<Filename, Error> {
            let (filename, data) = Self::create_filename_and_data(data)?;

            let path = Self::get_path(&filename);
            let mut file = File::create(path)?;

            file.write_all(&data)?;

            Ok(filename)
        }
    }

    pub trait FileHandler<T: Default> {
        // path to where the file should be saved
        const PATH: &'static str;

        fn deserialize_bytes(bytes: Vec<u8>) -> Result<T, Error>;

        fn check_slot_in_splitted_filename(slot_param: Slot, splits: &mut Split<&str>) -> bool;

        fn get_path(filename: &str) -> PathBuf {
            let mut path = PathBuf::new();
            path.push(Self::PATH);
            path.push(filename);
            path
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
                let filename = path?.file_name().into_string().unwrap();
                let mut splits = filename.split("_");

                if Self::check_slot_in_splitted_filename(slot_param, &mut splits) {
                    return Ok(filename);
                }
            }

            Err(Error::Other(format!(
                "Cannot find file for slot {}",
                slot_param
            )))
        }

        fn get_map_from_archives(slot: Slot) -> Result<T, Error> {
            let filename = Self::find_file_by_slot(slot)?;

            Self::read_file(&filename)
        }
    }
}

mod handler {
    use std::fs::{create_dir_all, File};
    use std::io::Write;
    use std::str::Split;

    use substrate_stellar_sdk::XdrCodec;

    use super::*;

    pub struct EnvelopesFileHandler;

    pub struct TxSetsFileHandler;

    pub struct TxHashesFileHandler;

    impl FileHandler<EnvelopesMap> for EnvelopesFileHandler {
        const PATH: &'static str = "./scp_envelopes";

        fn deserialize_bytes(bytes: Vec<u8>) -> Result<EnvelopesMap, Error> {
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

    impl FileHandlerExt<EnvelopesMap> for EnvelopesFileHandler {
        fn create_filename_and_data(
            data: &EnvelopesMap,
        ) -> Result<(Filename, SerializedData), Error> {
            let mut filename: Filename = "".to_string();
            let mut m: SlotEncodedMap = SlotEncodedMap::new();
            let len = data.len();

            for (idx, (key, value)) in data.iter().enumerate() {
                if idx == 0 {
                    filename.push_str(&format!("{}_", key));
                }

                if idx == (len - 1) {
                    filename.push_str(&format!("{}", key));
                }

                let stellar_array = UnlimitedVarArray::new(value.clone())?; //.map_err(Error::from)?;
                m.insert(*key, stellar_array.to_xdr());
            }

            let res = bincode::serialize(&m)?;

            Ok((filename, res))
        }
    }

    impl FileHandler<TxSetMap> for TxSetsFileHandler {
        const PATH: &'static str = "./tx_sets";

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
            EnvelopesFileHandler::check_slot_in_splitted_filename(slot_param, splits)
        }
    }

    impl FileHandlerExt<TxSetMap> for TxSetsFileHandler {
        fn create_filename_and_data(data: &TxSetMap) -> Result<(Filename, SerializedData), Error> {
            let mut filename: Filename = "".to_string();
            let mut m: SlotEncodedMap = SlotEncodedMap::new();
            let len = data.len();

            for (idx, (key, set)) in data.iter().enumerate() {
                if idx == 0 {
                    filename.push_str(&format!("{}_", key));
                }

                if idx == (len - 1) {
                    filename.push_str(&format!("{}", key));
                }

                m.insert(*key, set.to_xdr());
            }

            Ok((filename, bincode::serialize(&m)?))
        }
    }

    impl TxHashesFileHandler {
        fn create_data(data: &TxHashMap) -> Result<SerializedData, Error> {
            bincode::serialize(data).map_err(Error::from)
        }

        pub fn write_to_file(filename: Filename, data: &TxHashMap) -> Result<(), Error> {
            let path = Self::get_path(&filename);
            let mut file = File::create(path)?;

            let data = Self::create_data(data)?;
            file.write_all(&data).map_err(Error::from)
        }
    }

    impl FileHandler<TxHashMap> for TxHashesFileHandler {
        const PATH: &'static str = "./tx_hashes";

        fn deserialize_bytes(bytes: Vec<u8>) -> Result<TxHashMap, Error> {
            bincode::deserialize(&bytes).map_err(Error::from)
        }

        fn check_slot_in_splitted_filename(slot_param: Slot, splits: &mut Split<&str>) -> bool {
            TxSetsFileHandler::check_slot_in_splitted_filename(slot_param, splits)
        }
    }

    pub fn prepare_directories() -> Result<(), Error> {
        create_dir_all("./scp_envelopes")?;
        create_dir_all("./tx_sets")?;

        create_dir_all("./tx_hashes").map_err(Error::from)
    }
}

mod collector {
    use substrate_stellar_sdk::Memo;
    use substrate_stellar_sdk::types::{ScpStatementExternalize, ScpStatementPledges};

    use stellar_relay::helper::compute_non_generic_tx_set_content_hash;

    use super::*;

    pub struct ScpMessageCollector {
        /// holds the mapping of the Slot Number(key) and the ScpEnvelopes(value)
        envelopes_map: EnvelopesMap,
        /// holds the mapping of the Slot Number(key) and the TransactionSet(value)
        txset_map: TxSetMap,
        /// holds the mapping of the Transaction Hash(key) and the Slot Number(value)
        tx_hash_map: TxHashMap,
        /// Holds the transactions that still have to be processed but were not because not enough scp messages are available yet.
        pending_transactions: Vec<TransactionEnvelope>,
        public_network: bool,
    }

    impl ScpMessageCollector {
        pub fn new(public_network: bool) -> Self {
            ScpMessageCollector {
                envelopes_map: Default::default(),
                txset_map: Default::default(),
                tx_hash_map: Default::default(),
                pending_transactions: vec![],
                public_network,
            }
        }

        pub fn envelopes_map(&self) -> &EnvelopesMap {
            &self.envelopes_map
        }

        pub fn txset_map(&self) -> &TxSetMap {
            &self.txset_map
        }

        pub fn tx_hash_map(&self) -> &TxHashMap {
            &self.tx_hash_map
        }

        pub fn network(&self) -> &Network {
            if self.public_network {
                &PUBLIC_NETWORK
            } else {
                &TEST_NETWORK
            }
        }

        pub fn is_public(&self) -> bool {
            self.public_network
        }

        /// handles incoming ScpEnvelope.
        ///
        /// # Arguments
        ///
        /// * `env` - the ScpEnvelope
        /// * `txset_hash_map` - provides the slot number of the given Transaction Set Hash
        /// * `user` - The UserControl used for sending messages to Stellar Node
        pub(crate) async fn handle_envelope(
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
                        log::info!("Adding received SCP envelopes for slot {}", slot);

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
                    if value.len() < MIN_EXTERNALIZED_MESSAGES && keys_len < MAX_SLOTS_PER_FILE * 5
                    {
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
            let _ = EnvelopesFileHandler::write_to_file(&self.envelopes_map)?;

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
        pub(crate) async fn handle_tx_set(
            &mut self,
            set: &TransactionSet,
            txset_hash_map: &mut TxSetCheckerMap,
        ) -> Result<(), Error> {
            self.check_write_tx_set_to_file()?;

            // compute the tx_set_hash, to check what slot this set belongs too.
            let tx_set_hash = compute_non_generic_tx_set_content_hash(set);

            if let Some(slot) = txset_hash_map.remove(&tx_set_hash) {
                self.txset_map.insert(slot, set.clone());
                self.update_tx_hash_map(slot, set).await?;
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

            let filename = TxSetsFileHandler::write_to_file(&self.txset_map)?;

            TxHashesFileHandler::write_to_file(filename, &self.tx_hash_map)?;

            self.txset_map = TxSetMap::new();
            self.tx_hash_map = HashMap::new();

            Ok(())
        }

        /// maps the slot to the transactions of the TransactionSet
        async fn update_tx_hash_map(
            &mut self,
            slot: Slot,
            tx_set: &TransactionSet,
        ) -> Result<(), Error> {
            log::info!("Inserting received transaction set for slot {}", slot);


            // Collect tx hashes to build proofs, and transactions to validate
            tx_set.txes.get_vec().iter().for_each(|tx_env| {
                let tx_hash = tx_env.get_hash(self.network());

                fn check_memo(memo: &Memo) -> bool {
                    match memo {
                        Memo::MemoText(t) if t.len() > 0 => std::str::from_utf8(t.get_vec())
                            .and_then(|memo_text| Ok(memo_text.contains("demo")))
                            .unwrap_or(false),
                        // note/todo: After the demo we should actually consider keeping only
                        // hashes for transactions that have a MEMO_HASH and not even MEMO_TEXT),
                        // because according to the Stellar docs,
                        // MEMO_TEXT can only be 28-bytes long which would not be enough
                        // to store the identifier we need for spacewalk.
                        // Thus only transactions with MEMO_HASH will be interesting for spacewalk.
                        _ => false,
                    }
                }

                let save_tx = match tx_env {
                    TransactionEnvelope::EnvelopeTypeTxV0(value) => check_memo(&value.tx.memo),
                    TransactionEnvelope::EnvelopeTypeTx(value) => {
                        if is_tx_relevant(&value.tx) {
                            // Add transaction to pending transactions if it is not yet contained
                            if self.pending_transactions.iter().find(|tx| tx.get_hash(self.network()) == tx_hash).is_none() {
                                self.pending_transactions.push(tx_env.clone());
                            }
                        }
                        check_memo(&value.tx.memo)
                    }
                    TransactionEnvelope::EnvelopeTypeTxFeeBump(_) => false,
                    TransactionEnvelope::Default(code) => {
                        log::info!("Default: {:?}", code);
                        false
                    }
                };

                if save_tx {
                    self.tx_hash_map.insert(tx_hash, slot);
                }
            });

            // Store the handled transaction indices in a vec to be able to remove them later
            let mut handled_tx_indices = Vec::new();
            for (index, tx_env) in self.pending_transactions.iter().enumerate() {
                // Try to send validation proofs
                let handled = tx_handler::handle_tx(tx_env.clone(), self).await?;
                if handled {
                    handled_tx_indices.push(index);
                }
            }
            // Remove the handled transactions from the pending transactions
            for index in handled_tx_indices.iter().rev() {
                self.pending_transactions.remove(*index);
            }
            Ok(())
        }
    }

    pub fn get_tx_set_hash(x: &ScpStatementExternalize) -> Result<TxSetHash, Error> {
        let scp_value = x.commit.value.get_vec();
        scp_value[0..32].try_into().map_err(Error::from)
    }
}

mod tx_handler {
    use substrate_stellar_sdk::XdrCodec;

    use super::*;

    pub struct Proof {
        tx_env: TransactionEnvelope,
        envelopes: UnlimitedVarArray<ScpEnvelope>,
        tx_set: TransactionSet,
    }

    // Returns a bool indicating whether the transaction was successfully handled or not
    pub async fn handle_tx(
        tx_env: TransactionEnvelope,
        collector: &ScpMessageCollector,
    ) -> Result<bool, Error> {
        let api = OnlineClient::<PolkadotConfig>::new().await.unwrap();

        if let Some((envelopes, txset)) = build_proof(&tx_env, collector) {
            if collector.is_public() {
                if envelopes.len() < 20 {
                    log::info!("Not yet enough envelopes to build proof, current amount {:?}. Retrying in next loop...", envelopes.len());
                    return Ok(false);
                }
            } else {
                if envelopes.len() < 2 {
                    log::info!("Not yet enough envelopes to build proof, current amount {:?}. Retrying in next loop...", envelopes.len());
                    return Ok(false);
                }
            }
            log::info!("Sending proof for tx: {:?} with {:?} scp messages", tx_env.get_hash(collector.network()), envelopes.len());
            let (tx_env, envelopes, txset) = encode(tx_env, envelopes, txset);
            let tx = spacewalk_chain::tx()
                .stellar_relay()
                .validate_stellar_transaction_ext(
                    tx_env.as_bytes().to_vec(),
                    envelopes.as_bytes().to_vec(),
                    txset.as_bytes().to_vec(),
                    collector.is_public(),
                );
            let signer = PairSigner::new(AccountKeyring::Alice.pair());
            let hash = api.tx().sign_and_submit_default(&tx, &signer).await?;
            log::info!("Successfully submitted validate_stellar_transaction_ext() extrinsic: {:?}", hash);
        }

        Ok(true)
    }

    fn encode(
        tx_env: TransactionEnvelope,
        envelopes: UnlimitedVarArray<ScpEnvelope>,
        tx_set: TransactionSet,
    ) -> (String, String, String) {
        let tx_env_xdr = tx_env.to_xdr();
        let tx_env_encoded = base64::encode(tx_env_xdr);

        let envelopes_xdr = envelopes.to_xdr();
        let envelopes_encoded = base64::encode(envelopes_xdr);

        let tx_set_xdr = tx_set.to_xdr();
        let tx_set_encoded = base64::encode(tx_set_xdr);

        (tx_env_encoded, envelopes_encoded, tx_set_encoded)
    }

    fn build_proof(
        tx_env: &TransactionEnvelope,
        collector: &ScpMessageCollector,
    ) -> Option<(UnlimitedVarArray<ScpEnvelope>, TransactionSet)> {
        let tx_hash = tx_env.get_hash(collector.network());

        let slot = collector.tx_hash_map().get(&tx_hash)?;

        let tx_set = collector.txset_map().get(slot).cloned().or_else(|| {
            if let Ok(txset_map) = TxSetsFileHandler::get_map_from_archives(*slot) {
                txset_map.get(slot).cloned()
            } else {
                None
            }
        })?;

        let envelopes = collector.envelopes_map().get(slot).cloned().or_else(|| {
            if let Ok(envelopes_map) = EnvelopesFileHandler::get_map_from_archives(*slot) {
                envelopes_map.get(slot).cloned()
            } else {
                None
            }
        })?;
        let envelopes =
            UnlimitedVarArray::new(envelopes.clone()).unwrap_or(UnlimitedVarArray::new_empty());

        Some((envelopes, tx_set))
    }
}

fn is_tx_relevant(transaction: &Transaction) -> bool {
    let payment_ops_to_vault_address: Vec<&PaymentOp> = transaction
        .operations
        .get_vec()
        .into_iter()
        .filter_map(|op| match &op.body {
            substrate_stellar_sdk::types::OperationBody::Payment(p) => {
                let d = p.destination.clone();
                if VAULT_ADDRESSES_FILTER
                    .contains(&std::str::from_utf8(d.to_encoding().as_slice()).unwrap())
                {
                    Some(p)
                } else {
                    None
                }
            }
            _ => None,
        })
        .collect();

    if payment_ops_to_vault_address.len() == 0 {
        // The transaction is not relevant to use since it doesn't
        // include a payment to our vault address
        return false;
    } else {
        log::info!("Transaction to our vault address received.");
        let source = transaction.source_account.clone();
        for payment_op in payment_ops_to_vault_address {
            let destination = payment_op.destination.clone();
            let amount = payment_op.amount;
            let asset = payment_op.asset.clone();
            log::info!("Deposit amount {:?} stroops", amount);
            // print_asset(asset);
            log::info!(
                "From {:#?}",
                std::str::from_utf8(source.to_encoding().as_slice()).unwrap()
            );
            log::info!(
                "To {:?}",
                std::str::from_utf8(destination.to_encoding().as_slice()).unwrap()
            );
        }
        return true;
    }
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

#[subxt::subxt(runtime_metadata_path = "metadata.scale")]
pub mod spacewalk_chain {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    prepare_directories()?;

    let args: Vec<String> = std::env::args().collect();
    let arg_network = &args[1];
    let mut public_network = false;
    let mut tier1_node_ip = TIER_1_VALIDATOR_IP_TESTNET;

    if arg_network == "mainnet" {
        public_network = true;
        tier1_node_ip = TIER_1_VALIDATOR_IP_PUBLIC;
    }
    let network: &Network = if public_network {
        &PUBLIC_NETWORK
    } else {
        &TEST_NETWORK
    };

    log::info!(
        "Connected to {:?} through {:?}",
        std::str::from_utf8(network.get_passphrase().as_slice()).unwrap(),
        tier1_node_ip
    );

    let secret =
        SecretKey::from_encoding("SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73")
            .unwrap();

    let node_info = NodeInfo::new(19, 21, 19, "v19.1.0".to_string(), network);
    let cfg = ConnConfig::new(tier1_node_ip, 11625, secret, 0, true, true, false);
    let mut user: UserControls = connect(node_info, cfg).await?;
    let mut collector = ScpMessageCollector::new(public_network);

    let mut tx_set_hash_map: TxSetCheckerMap = HashMap::new();

    while let Some(conn_state) = user.recv().await {
        match conn_state {
            StellarNodeMessage::Data {
                p_id: _,
                msg_type: _,
                msg,
            } => match msg {
                StellarMessage::ScpMessage(env) => {
                    collector
                        .handle_envelope(env, &mut tx_set_hash_map, &user)
                        .await?;
                }
                StellarMessage::TxSet(set) => {
                    // log::info!("---- PID: {} Handle {:?}----", p_id, msg_type);
                    collector.handle_tx_set(&set, &mut tx_set_hash_map).await?;
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
    use std::env;

    use substrate_stellar_sdk::types::ScpStatementPledges;

    use stellar_relay::helper::compute_non_generic_tx_set_content_hash;

    use super::*;

    #[test]
    fn find_file_successful() {
        let slot = 42867089;

        let file_name =
            EnvelopesFileHandler::find_file_by_slot(slot).expect("should return a file");
        assert_eq!(&file_name, "42867088_42867102");

        let file_name = TxSetsFileHandler::find_file_by_slot(slot).expect("should return a file");
        assert_eq!(&file_name, "42867088_42867102");

        let file_name = TxHashesFileHandler::find_file_by_slot(slot).expect("should return a file");
        assert_eq!(&file_name, "42867088_42867102");

        let slot = 42867150;

        let file_name =
            EnvelopesFileHandler::find_file_by_slot(slot).expect("should return a file");
        assert_eq!(&file_name, "42867148_42867162");

        let file_name = TxSetsFileHandler::find_file_by_slot(slot).expect("should return a file");
        assert_eq!(&file_name, "42867135_42867150");

        let file_name = TxHashesFileHandler::find_file_by_slot(slot).expect("should return a file");
        assert_eq!(&file_name, "42867135_42867150");

        let slot = 42990037;
        let file_name =
            EnvelopesFileHandler::find_file_by_slot(slot).expect("should return a file");
        assert_eq!(&file_name, "42990036_42990037");
    }

    #[test]
    fn read_file_successful() {
        let first_slot = 42867118;
        let last_slot = 42867132;

        let envelopes_map =
            EnvelopesFileHandler::read_file(&format!("{}_{}", first_slot, last_slot))
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

        let filename =
            TxSetsFileHandler::find_file_by_slot(last_slot).expect("should return a filename");
        let txset_map = TxSetsFileHandler::read_file(&filename).expect("should return a txset map");

        let txset = txset_map.get(&last_slot).expect("should have a txset");
        let tx_set_hash = compute_non_generic_tx_set_content_hash(txset);

        let first = scp_envelopes.first().expect("should return an envelope");

        if let ScpStatementPledges::ScpStExternalize(stmt) = &first.statement.pledges {
            let expected_tx_set_hash = get_tx_set_hash(&stmt).expect("return a tx set hash");

            assert_eq!(tx_set_hash, expected_tx_set_hash);
        } else {
            assert!(false);
        }

        let txes = txset.txes.get_vec();
        let idx = txes.len() / 2;
        let tx = txes.get(idx).expect("should return a tx envelope.");

        let network = Network::new(b"Public Global Stellar Network ; September 2015");

        let hash = tx.get_hash(&network);
        let txhash_map =
            TxHashesFileHandler::read_file(&filename).expect("should return txhash map");
        let actual_slot = txhash_map.get(&hash).expect("should return a slot number");
        assert_eq!(actual_slot, &last_slot);
    }
}
