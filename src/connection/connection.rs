#![allow(dead_code)] //todo: remove after being tested and implemented

use crate::connection::authentication::{verify_remote_auth_cert, ConnectionAuth};
use crate::connection::handshake::create_hello_message;
use crate::connection::Error as ConnectionError;
use std::time::{SystemTime, UNIX_EPOCH};
use substrate_stellar_sdk::types::{
    AuthenticatedMessage, AuthenticatedMessageV0, Curve25519Public, Hello, HmacSha256Mac,
    StellarMessage, Uint256,
};
use substrate_stellar_sdk::{PublicKey, SecretKey, XdrCodec};

use crate::helper::{create_sha256_hmac, generate_random_nonce};
use crate::node::NodeInfo;

pub struct Connection {
    pub local_sequence: u64,
    pub local_nonce: Uint256,
    pub local_node: NodeInfo,
    pub local_listening_port: u32,
    pub remote_pub_key_ecdh: Option<Curve25519Public>,
    pub remote_pub_key: Option<PublicKey>,
    pub remote_nonce: Option<Uint256>,
    pub remote_node: Option<NodeInfo>,
    pub sending_mac_key: Option<PublicKey>,
    connection_auth: ConnectionAuth,
}

impl Connection {
    #[cfg(feature = "mock_data")]
    pub fn new_mock(
        local_node: NodeInfo,
        keypair: SecretKey,
        auth_cert_expiration: u64,
        local_nonce: Uint256,
        secret_key_ecdh: &str,
    ) -> Connection {
        let connection_auth = ConnectionAuth::new_with_key(
            local_node.network_id(),
            keypair,
            auth_cert_expiration,
            secret_key_ecdh,
        );

        Connection {
            local_sequence: 0,
            local_nonce,
            local_node,
            local_listening_port: 11625,
            remote_pub_key_ecdh: None,
            remote_pub_key: None,
            remote_nonce: None,
            remote_node: None,
            sending_mac_key: None,
            connection_auth,
        }
    }

    pub fn new(local_node: NodeInfo, keypair: SecretKey, auth_cert_expiration: u64) -> Connection {
        let connection_auth =
            ConnectionAuth::new(local_node.network_id(), keypair, auth_cert_expiration);

        Connection {
            local_sequence: 0,
            local_nonce: generate_random_nonce(),
            local_node,
            local_listening_port: 11625,
            remote_pub_key_ecdh: None,
            remote_pub_key: None,
            remote_nonce: None,
            remote_node: None,
            sending_mac_key: None,
            connection_auth,
        }
    }

    /// Returns HmacSha256Mac
    fn mac(&self, message: &StellarMessage) -> HmacSha256Mac {
        let empty = HmacSha256Mac { mac: [0; 32] };

        if self.remote_pub_key_ecdh.is_none() || self.sending_mac_key.is_none() {
            return empty;
        }

        match &self.sending_mac_key {
            None => empty,
            Some(key) => {
                let mut buffer = self.local_sequence.to_xdr();
                buffer.append(&mut message.to_xdr());

                create_sha256_hmac(&buffer, key.as_binary())
            }
        }
    }

    /// Wraps the stellar message with `AuthenticatedMessage
    pub fn authenticate_message(&mut self, message: StellarMessage) -> AuthenticatedMessage {
        let mac = self.mac(&message);
        let sequence = self.local_sequence;

        match &message {
            StellarMessage::ErrorMsg(_) | StellarMessage::Hello(_) => {}
            _ => self.local_sequence += 1,
        }

        let auth_message_v0 = AuthenticatedMessageV0 {
            sequence,
            message,
            mac,
        };

        AuthenticatedMessage::V0(auth_message_v0)
    }

    fn _create_hello_message(&mut self, valid_at: u64) -> StellarMessage {
        let auth_cert = self.connection_auth.generate_and_save_auth_cert(valid_at);
        let peer_id = self.connection_auth.keypair().get_public();

        create_hello_message(
            peer_id.clone(),
            self.local_nonce,
            auth_cert,
            self.local_listening_port,
            &self.local_node,
        )
    }

    #[cfg(feature = "mock_data")]
    pub fn create_hello_message_mock_time(&mut self, valid_at: u64) -> StellarMessage {
        self._create_hello_message(valid_at)
    }

    pub fn create_hello_message(&mut self) -> StellarMessage {
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let time_now = u64::try_from(time_now).unwrap();

        self._create_hello_message(time_now)
    }

    fn process_hello_message(&mut self, hello: Hello) -> Result<(), ConnectionError> {
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let time_now = u64::try_from(time_now).unwrap();

        let mut network_id = self.connection_auth.network_id().to_xdr();
        if !verify_remote_auth_cert(time_now, &hello.peer_id, &hello.cert, &mut network_id) {
            return Err(ConnectionError::AuthCertInvalid);
        }

        self.remote_nonce = Some(hello.nonce);
        self.remote_pub_key_ecdh = Some(hello.cert.pubkey);

        Ok(())
    }
}
