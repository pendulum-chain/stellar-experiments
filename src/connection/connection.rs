#![allow(dead_code)] //todo: remove after being tested and implemented

use std::time::{SystemTime, UNIX_EPOCH};
use substrate_stellar_sdk::{PublicKey, XdrCodec};
use substrate_stellar_sdk::types::{AuthenticatedMessage, AuthenticatedMessageV0, Curve25519Public, Error as SubstrateStellarError, Hello, HmacSha256Mac, StellarMessage, Uint256};
use crate::connection::authentication::{ConnectionAuth, create_sha256_hmac, verify_remote_auth_cert};
use crate::connection::Error as ConnectionError;
use crate::connection::handshake::create_hello_message;
use crate::generate_random_nonce;
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
    pub fn new(local_node: NodeInfo, connection_auth:ConnectionAuth) -> Connection {
        Connection {
            local_sequence: 0,
            local_nonce:generate_random_nonce(),
            local_node,
            local_listening_port: 11625,
            remote_pub_key_ecdh: None,
            remote_pub_key: None,
            remote_nonce: None,
            remote_node: None,
            sending_mac_key: None,
            connection_auth
        }
    }

    /// Returns HmacSha256Mac
    fn mac(&self, message: &StellarMessage) -> HmacSha256Mac {
        let empty = HmacSha256Mac {
            mac: [0; 32]
        };

        if self.remote_pub_key_ecdh.is_none() || self.sending_mac_key.is_none() {
            return empty;
        }

        match &self.sending_mac_key {
            None => { empty }
            Some(key) => {
                let mut buffer = self.local_sequence.to_xdr();
                buffer.append(&mut message.to_xdr());

                create_sha256_hmac(&buffer,key.as_binary())
            }
        }
    }

    /// Wraps the stellar message with `AuthenticatedMessage
    pub fn authenticate_message(&mut self, message: StellarMessage) -> AuthenticatedMessage {
        let mac = self.mac(&message);
        let sequence = self.local_sequence;

        match &message {
            StellarMessage::ErrorMsg(_) |  StellarMessage::Hello(_)=> {}
            _ => self.local_sequence +=1
        }

        let auth_message_v0 = AuthenticatedMessageV0 {
            sequence,
            message,
            mac
        };

        AuthenticatedMessage::V0(auth_message_v0)
    }

    pub fn create_hello_message(&mut self) -> StellarMessage {
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let time_now = u64::try_from(time_now).unwrap();

        let auth_cert = self.connection_auth.generate_and_save_auth_cert(time_now);
        let peer_id = self.connection_auth.keypair().get_public();

        create_hello_message(
            peer_id.clone(),
            self.local_nonce,
            auth_cert,
            self.local_listening_port,
            &self.local_node
        )
    }

    fn process_hello_message(&mut self, hello: Hello) -> Result<(),ConnectionError> {
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let time_now = u64::try_from(time_now).unwrap();

        let mut network_id = self.connection_auth.network_id().to_xdr();
        if !verify_remote_auth_cert(
            time_now,
            &hello.peer_id,
            &hello.cert,
            &mut network_id
        ) {
            return Err(ConnectionError::AuthCertInvalid);
        }

        self.remote_nonce = Some(hello.nonce);
        self.remote_pub_key_ecdh = Some(hello.cert.pubkey);

        Ok(())
    }
}