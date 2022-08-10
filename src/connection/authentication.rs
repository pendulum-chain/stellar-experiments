#![allow(dead_code)] //todo: remove after being tested and implemented

use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Sha256, Digest};
use std::collections::HashMap;

use substrate_stellar_sdk::network::Network;
use substrate_stellar_sdk::types::{AuthCert, Curve25519Public, EnvelopeType, HmacSha256Mac, Signature, Uint256};
use substrate_stellar_sdk::{Curve25519Secret, PublicKey, SecretKey, XdrCodec};
use crate::connection::Error;

type Buffer = [u8; 32];
type KeyAsBinary = [u8; 32];
type HmacSha256 = Hmac<Sha256>;

pub const AUTH_CERT_EXPIRATION_LIMIT: u64 = 360000; // 60 minutes


pub struct ConnectionAuth {
    keypair: SecretKey,
    secret_key_ecdh: Curve25519Secret,
    pub_key_ecdh: Curve25519Public,
    network: Network,
    we_called_remote_shared_keys: HashMap<KeyAsBinary, HmacSha256Mac>,
    remote_called_us_shared_keys: HashMap<KeyAsBinary, HmacSha256Mac>,
    auth_cert: Option<AuthCert>,
    auth_cert_expiration: u64,
}

impl ConnectionAuth {
    pub fn new(network: Network, keypair: SecretKey, auth_cert_expiration: u64) -> ConnectionAuth {
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
            auth_cert: None,
            auth_cert_expiration,
        }
    }

    pub(crate) fn keypair(&self) -> &SecretKey {
        &self.keypair
    }

    pub fn pub_key_ecdh(&self) -> &Curve25519Public {
        &self.pub_key_ecdh
    }

    pub fn network_id(&self) -> &Buffer {
        self.network.get_id()
    }

    /// Gets an existing shared key.
    /// Returns `none` when not found.
    pub fn shared_key(
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
    pub fn generate_and_save_shared_key(
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

    ///  Returns none if the validity start date exceeds the expiration
    ///  or if an auth cert was never created in the first place.
    ///
    /// # Arguments
    /// * `valid_at` - the validity start date in seconds.
    pub fn auth_cert(&self, valid_at: u64) -> Result<&AuthCert, Error> {
        match self.auth_cert.as_ref() {
            None => Err(Error::AuthCertNotFound),
            Some(auth_cert) => {
                if self.auth_cert_expiration < (valid_at + AUTH_CERT_EXPIRATION_LIMIT / 2) {
                    return Err(Error::AuthCertExpired);
                }
                Ok(auth_cert)
            }
        }
    }

    pub fn generate_and_save_auth_cert(&mut self, valid_at: u64) -> AuthCert {
        let mut network_id_xdr = self.network.get_id().to_xdr();
        self.auth_cert_expiration = valid_at + AUTH_CERT_EXPIRATION_LIMIT;

        println!("AUTH CERT EXPIRATION: {}", self.auth_cert_expiration);
        let auth_cert = create_auth_cert(
            self.auth_cert_expiration,
            &mut network_id_xdr,
            self.pub_key_ecdh.clone(),
            &self.keypair,
        );

        self.auth_cert = Some(auth_cert.clone());
        auth_cert
    }
}

pub fn create_sha256_hmac(data_buffer: &[u8], mac_key_buffer: &Buffer) -> HmacSha256Mac {
    let mut hmac = HmacSha256::new_from_slice(mac_key_buffer).unwrap();
    hmac.update(data_buffer);
    let hmac = hmac.finalize().into_bytes().to_vec();

    HmacSha256Mac {
        mac: hmac.try_into().unwrap(),
    }
}


pub fn verify_hmac(data_buffer: &[u8], mac_key_buffer: &Buffer, mac: &Buffer) -> Result<(),Error> {
    let mut hmac = HmacSha256::new_from_slice(mac_key_buffer).unwrap();
    hmac.update(data_buffer);

    hmac.verify_slice(mac).map_err(|e| Error::HmacError(e))

}

fn create_mac_key(shared_key: &HmacSha256Mac,
                  local_nonce: Uint256,
                  remote_nonce: Uint256,
                  mut buf:Vec<u8> ) -> HmacSha256Mac {
    let mut local_n = local_nonce.to_vec();
    let mut remote_n = remote_nonce.to_vec();

    buf.append(&mut local_n);
    buf.append(&mut remote_n);
    buf.append(&mut vec![1]);

    create_sha256_hmac(&buf,&shared_key.mac )
}

pub fn create_sending_mac_key(
    shared_key: &HmacSha256Mac,
    local_nonce: Uint256,
    remote_nonce: Uint256,
    we_called_remote: bool
) -> HmacSha256Mac {
    let mut buf: Vec<u8> = vec![];

    if we_called_remote {
        buf.append(&mut vec![0]);
    } else {
        buf.append(&mut vec![1]);
    }

    let mut local_n = local_nonce.to_vec();
    let mut remote_n = remote_nonce.to_vec();

    buf.append(&mut local_n);
    buf.append(&mut remote_n);
    buf.append(&mut vec![1]);

    create_sha256_hmac(&buf,&shared_key.mac )
}

pub fn create_receiving_mac_key(
    shared_key: &HmacSha256Mac,
    local_nonce: Uint256,
    remote_nonce: Uint256,
    we_called_remote: bool
) -> HmacSha256Mac {
    let mut buf: Vec<u8> = vec![];

    if we_called_remote {
        buf.append(&mut vec![1]);
    } else {
        buf.append(&mut vec![0]);
    }

    let mut local_n = local_nonce.to_vec();
    let mut remote_n = remote_nonce.to_vec();

    buf.append(&mut remote_n);
    buf.append(&mut local_n);
    buf.append(&mut vec![1]);

    create_sha256_hmac(&buf,&shared_key.mac )
}


fn create_auth_cert(
    expiration: u64,
    network_id_xdr: &mut Vec<u8>,
    pub_key_ecdh: Curve25519Public,
    secret: &SecretKey,
) -> AuthCert {
    let mut buf: Vec<u8> = vec![];

    buf.append(network_id_xdr);
    buf.append(&mut EnvelopeType::EnvelopeTypeAuth.to_xdr());
    buf.append(&mut expiration.to_xdr());
    buf.append(&mut pub_key_ecdh.key.to_vec());

    let mut hash = Sha256::new();
    hash.update(buf);

    let buf = hash.finalize().to_vec();

    let signature: Signature = Signature::new(secret.create_signature(buf).to_vec()).unwrap();

    AuthCert {
        pubkey: pub_key_ecdh,
        expiration,
        sig: signature,
    }
}

pub fn verify_remote_auth_cert(
    time_in_secs: u64,
    remote_pub_key: &PublicKey,
    auth_cert: &AuthCert,
    network_id_xdr: &mut [u8],
) -> bool {
    let expiration = auth_cert.expiration;
    if expiration <= (time_in_secs / 1000) {
        return false;
    }

    let mut raw_data: Vec<u8> = vec![];
    raw_data.extend_from_slice(network_id_xdr);
    raw_data.append(&mut EnvelopeType::EnvelopeTypeAuth.to_xdr());
    raw_data.append(&mut auth_cert.expiration.to_xdr());

    raw_data.append(&mut auth_cert.pubkey.key.to_vec());

    let raw_sig: [u8; 64] = auth_cert.sig.get_vec().clone().try_into().unwrap();
    remote_pub_key.verify_signature(raw_data, &raw_sig)
}

// Returns a new BigNumber with a pseudo-random value equal to or greater than 0 and less than 1.
pub fn generate_random_nonce() -> Uint256 {
    let mut rng = rand::thread_rng();
    let random_float = rng.gen_range(0.00..1.00);
    let mut hash = Sha256::new();
    hash.update(random_float.to_string());

    hash.finalize().to_vec().try_into().unwrap()
}

#[cfg(test)]
mod test {
    use crate::connection::authentication::{create_auth_cert, verify_remote_auth_cert, ConnectionAuth, AUTH_CERT_EXPIRATION_LIMIT, create_receiving_mac_key, create_sending_mac_key, create_sha256_hmac, verify_hmac, generate_random_nonce};
    use std::time::{SystemTime, UNIX_EPOCH};

    use sha2::{Sha256, Digest};
    use substrate_stellar_sdk::network::Network;
    use substrate_stellar_sdk::types::{Curve25519Public, HmacSha256Mac, Uint256};
    use substrate_stellar_sdk::{PublicKey, SecretKey, XdrCodec};
    use crate::connection::Error;

    fn mock_connection_auth() -> ConnectionAuth {
        let public_network = Network::new(b"Public Global Stellar Network ; September 2015");
        let secret =
            SecretKey::from_encoding("SCV6Q3VU4S52KVNJOFXWTHFUPHUKVYK3UV2ISGRLIUH54UGC6OPZVK2D")
                .expect("should work");

        ConnectionAuth::new(public_network, secret, 0)
    }

    #[test]
    fn create_valid_auth_cert() {
        let mut auth = mock_connection_auth();

        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let auth_cert = auth.generate_and_save_auth_cert(time_now);

        let mut network_id_xdr = auth.network.get_id().to_xdr();
        let mut pub_key = auth.keypair.get_public();
        assert!(verify_remote_auth_cert(
            time_now,
            pub_key,
            &auth_cert,
            &mut network_id_xdr
        ));
    }

    #[test]
    fn expired_auth_cert() {
        let mut auth = mock_connection_auth();

        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(auth.auth_cert(time_now), Err(Error::AuthCertNotFound));

        let new_auth = auth.generate_and_save_auth_cert(time_now);
        let auth_inside_valid_range = auth
            .auth_cert(time_now + 1)
            .expect("should return an auth cert");
        assert_eq!(&new_auth, auth_inside_valid_range);

        // expired
        let new_time = time_now + (AUTH_CERT_EXPIRATION_LIMIT / 2) + 100;
        assert_eq!(auth.auth_cert(new_time), Err(Error::AuthCertExpired));
    }

    #[test]
    fn create_valid_shared_key() {
        let public_network = Network::new(b"Public Global Stellar Network ; September 2015");
        let secret =
            SecretKey::from_encoding("SCV6Q3VU4S52KVNJOFXWTHFUPHUKVYK3UV2ISGRLIUH54UGC6OPZVK2D")
                .expect("should work");

        let mut auth = ConnectionAuth::new(public_network, secret, 0);

        let bytes = base64::decode_config(
            "SaINZpCTl6KO8xMLvDkE2vE3knQz0Ma1RmJySOFqsWk=",
            base64::STANDARD,
        )
        .unwrap();
        let remote_pub_key = PublicKey::from_binary(bytes.try_into().unwrap());

        assert!(auth.shared_key(&remote_pub_key, true).is_none());

        let shared_key = auth.generate_and_save_shared_key(&remote_pub_key, true);

        assert_eq!(auth.shared_key(&remote_pub_key, true), Some(&shared_key));
    }

    #[test]
    fn mac_test() {

        fn data_message() -> Vec<u8> {
            let mut peer_sequence = 10u64.to_xdr();

            let mut message = base64::decode_config(
                "AAAAAAAAAAAAAAE3AAAACwAAAACslTOENMyaVlaiRvFAjiP6s8nFVIHDgWGbncnw+ziO5gAAAAACKbcUAAAAAzQaCq4p6tLHpdfwGhnlyX9dMUP70r4Dm98Td6YvKnhoAAAAAQAAAJijLxoAW1ZSaVphczIXU0XT7i46Jla6OZxkm9mEUfan3gAAAABg6Ee9AAAAAAAAAAEAAAAA+wsSteGzmcH88GN69FRjGLfxMzFH8tsJTaK+8ERePJMAAABAOiGtC3MiMa3LVn8f6SwUpKOmSMAJWQt2vewgt8T9WkRUPt2UdYac7vzcisXnmiusHldZcjVMF3vS03QhzaxdDQAAAAEAAACYoy8aAFtWUmlaYXMyF1NF0+4uOiZWujmcZJvZhFH2p94AAAAAYOhHvQAAAAAAAAABAAAAAPsLErXhs5nB/PBjevRUYxi38TMxR/LbCU2ivvBEXjyTAAAAQDohrQtzIjGty1Z/H+ksFKSjpkjACVkLdr3sILfE/VpEVD7dlHWGnO783IrF55orrB5XWXI1TBd70tN0Ic2sXQ0AAABA0ZiyH9AGgPR/d3h+94s6+iU5zhZbKM/5DIOYeKgxwEOotUveGfHLN5IQk7VlTW2arDkk+ekzjRQfBoexrkJrBMsQ30YpI1R/uY9npg0Fpt1ScyZ+yhABs6x1sEGminNh",
                base64::STANDARD,
            ).unwrap();

            let mut buf = vec![];
            buf.append(&mut peer_sequence);
            buf.append(&mut message);

            buf
        }

        let mut con_auth = mock_connection_auth();

        let public_network = Network::new(b"Public Global Stellar Network ; September 2015");
        let secret =
            SecretKey::from_encoding("SDAL6QYZG7O26OTLLP7JLNSB6SHY3CBZGJAWDPHYMRW2J3D2SA2RWU3L")
                .expect("should work");
        let mut peer_auth = ConnectionAuth::new(public_network, secret, 0);

        let our_nonce = generate_random_nonce();
        let peer_nonce = generate_random_nonce();

        let recv_mac_key = {
            let remote_pub_key = PublicKey::from_binary(peer_auth.pub_key_ecdh.key);
            let shared_key = con_auth.generate_and_save_shared_key(&remote_pub_key,true);

            create_receiving_mac_key(&shared_key,our_nonce,peer_nonce,true)
        };

        let peer_sending_mac_key = {
            let remote_pub_key = PublicKey::from_binary(con_auth.pub_key_ecdh.key);
            let shared_key = peer_auth.generate_and_save_shared_key(&remote_pub_key,false);

            create_sending_mac_key(&shared_key,peer_nonce,our_nonce,false)
        };

        let mut mac_peer_uses_to_send_us_msg =
            create_sha256_hmac(&data_message(),&peer_sending_mac_key.mac);

        assert!(
            verify_hmac(
                &data_message(),
                &recv_mac_key.mac,
                &mac_peer_uses_to_send_us_msg.mac
            ).is_ok()
        );
    }
}
