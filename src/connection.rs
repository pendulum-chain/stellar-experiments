use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use std::collections::HashMap;

use substrate_stellar_sdk::network::Network;
use substrate_stellar_sdk::types::{AuthCert, Curve25519Public, HmacSha256Mac, Signature, Uint256};
use substrate_stellar_sdk::{Curve25519Secret, PublicKey, SecretKey, XdrCodec};

type Buffer = [u8; 32];

fn env_type_auth() -> Vec<u8> {
    b"envelopeTypeAuth".to_xdr()
}

pub struct ConnectionAuth {
    keypair: SecretKey,
    secret_key_ecdh: Curve25519Secret,
    pub_key_ecdh: Curve25519Public,
    network: Network,
    we_called_remote_shared_keys: HashMap<[u8; 32], HmacSha256Mac>,
    remote_called_us_shared_keys: HashMap<[u8; 32], HmacSha256Mac>,
}

impl ConnectionAuth {
    fn new(network: Network, keypair: SecretKey) -> ConnectionAuth {
        let secret_key = rand::thread_rng().gen::<Buffer>();
        let mut pub_key: Buffer = [0; 32];
        tweetnacl::scalarmult_base(&mut pub_key, &secret_key);

        ConnectionAuth {
            keypair,
            secret_key_ecdh: Curve25519Secret { key: secret_key },
            pub_key_ecdh: Curve25519Public { key: pub_key },
            network,
            we_called_remote_shared_keys: HashMap::new(),
            remote_called_us_shared_keys: HashMap::new(),
        }
    }

    /// Gets an existing shared key.
    /// Returns `none` when not found.
    fn get_shared_key(
        &self,
        remote_pub_key: &PublicKey,
        we_called_remote: bool,
    ) -> Option<&HmacSha256Mac> {
        let shared_keys_map = if we_called_remote {
            &self.we_called_remote_shared_keys
        } else {
            &self.remote_called_us_shared_keys
        };

        shared_keys_map.get(remote_pub_key.as_binary())
    }

    /// Generates a new shared key, and saves it in the map.
    fn generate_and_save_shared_key(
        &mut self,
        remote_pub_key: &PublicKey,
        we_called_remote: bool,
    ) -> HmacSha256Mac {
        // prepare the buffers
        let mut final_buffer: Vec<u8> = vec![];
        let mut buffer: Buffer = [0; 32];

        let remote_pub_key_bin = remote_pub_key.as_binary();
        tweetnacl::scalarmult(&mut buffer, &self.secret_key_ecdh.key, remote_pub_key_bin);

        final_buffer.extend_from_slice(&buffer);
        if we_called_remote {
            final_buffer.extend_from_slice(&self.pub_key_ecdh.key);
            final_buffer.extend_from_slice(remote_pub_key_bin);
        } else {
            final_buffer.extend_from_slice(remote_pub_key_bin);
            final_buffer.extend_from_slice(&self.pub_key_ecdh.key);
        }

        // create hmac
        let shared_key = create_sha256_hmac(&final_buffer, &[0; 32]);

        // save the hmac
        if we_called_remote {
            self.we_called_remote_shared_keys
                .insert(*remote_pub_key_bin, shared_key.clone());
        } else {
            self.remote_called_us_shared_keys
                .insert(*remote_pub_key_bin, shared_key.clone());
        };

        shared_key
    }
}

pub fn create_sha256_hmac(data_buffer: &[u8], mac_key_buffer: &Buffer) -> HmacSha256Mac {
    type HmacSha256 = Hmac<Sha256>;

    let mut hmac = HmacSha256::new_from_slice(mac_key_buffer).unwrap();
    hmac.update(data_buffer);
    let hmac = hmac.finalize().into_bytes().to_vec();

    HmacSha256Mac {
        mac: hmac.try_into().unwrap(),
    }
}

fn create_auth_cert(
    time_now: u64,
    network_id_xdr: &mut Vec<u8>,
    pub_key: &PublicKey,
    secret: &SecretKey,
) -> AuthCert {
    let auth_expiration_limit: u64 = 3600;
    let expiration = time_now + auth_expiration_limit;

    let mut buf: Vec<u8> = vec![];

    buf.append(network_id_xdr);
    buf.append(&mut env_type_auth());
    buf.append(&mut expiration.to_xdr());
    buf.append(&mut pub_key.to_xdr());

    let signature: Signature = Signature::new(secret.create_signature(buf).to_vec()).unwrap();

    AuthCert {
        pubkey: Curve25519Public {
            key: pub_key.clone().into_binary(),
        },
        expiration,
        sig: signature,
    }
}

fn verify_remote_auth_cert(
    time_in_secs: u64,
    remote_pub_key: &PublicKey,
    auth_cert: &AuthCert,
    network_id_xdr: &mut Vec<u8>,
) -> bool {
    let expiration = auth_cert.expiration;
    if expiration <= (time_in_secs / 1000) {
        //TODO: not really sure of the 1000
        return false;
    }

    let mut raw_data: Vec<u8> = vec![];
    raw_data.append(network_id_xdr);
    raw_data.append(&mut env_type_auth());
    raw_data.append(&mut auth_cert.expiration.to_xdr());

    let pubkey = PublicKey::from_binary(auth_cert.pubkey.key);
    raw_data.append(&mut pubkey.to_xdr());

    let raw_sig: [u8; 64] = auth_cert.sig.get_vec().clone().try_into().unwrap();
    remote_pub_key.verify_signature(raw_data, &raw_sig)
}

fn create_sending_mac_key(
    local_nonce: Uint256,
    remote_nonce: Uint256,
    remote_pub_key: Curve25519Public,
    we_called_remote: bool,
) {
    let mut local_n = local_nonce.to_vec();
    let mut remote_n = remote_nonce.to_vec();

    let mut buf: Vec<u8> = vec![];

    if we_called_remote {
        buf.append(&mut vec![0]);
    } else {
        buf.append(&mut vec![1]);
    }

    buf.append(&mut local_n);
    buf.append(&mut remote_n);
    buf.append(&mut vec![1]);
}

#[cfg(test)]
mod test {

    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::connection::{create_auth_cert, verify_remote_auth_cert, ConnectionAuth};
    use substrate_stellar_sdk::network::Network;
    use substrate_stellar_sdk::types::Curve25519Public;
    use substrate_stellar_sdk::{PublicKey, SecretKey, XdrCodec};

    #[test]
    fn create_valid_auth_cert() {
        let secret =
            SecretKey::from_encoding("SCV6Q3VU4S52KVNJOFXWTHFUPHUKVYK3UV2ISGRLIUH54UGC6OPZVK2D")
                .expect("should be okay");
        let pub_key = secret.get_public();
        let public_network = Network::new(b"Public Global Stellar Network ; September 2015");

        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut network_id_xdr = public_network.get_id().to_xdr();
        let auth_cert = create_auth_cert(time_now, &mut network_id_xdr, pub_key, &secret);

        let mut network_id_xdr = public_network.get_id().to_xdr();
        assert!(verify_remote_auth_cert(
            time_now,
            pub_key,
            &auth_cert,
            &mut network_id_xdr
        ));
    }

    #[test]
    fn create_valid_shared_key() {
        let public_network = Network::new(b"Public Global Stellar Network ; September 2015");
        let secret =
            SecretKey::from_encoding("SCV6Q3VU4S52KVNJOFXWTHFUPHUKVYK3UV2ISGRLIUH54UGC6OPZVK2D")
                .expect("should work");

        let mut auth = ConnectionAuth::new(public_network, secret);

        let bytes = base64::decode_config(
            "SaINZpCTl6KO8xMLvDkE2vE3knQz0Ma1RmJySOFqsWk=",
            base64::STANDARD,
        )
        .unwrap();
        let remote_pub_key = PublicKey::from_binary(bytes.try_into().unwrap());

        assert!(auth.get_shared_key(&remote_pub_key, true).is_none());

        let shared_key = auth.generate_and_save_shared_key(&remote_pub_key, true);

        assert_eq!(
            auth.get_shared_key(&remote_pub_key, true),
            Some(&shared_key)
        );
    }
}
