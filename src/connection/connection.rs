#![allow(dead_code)] //todo: remove after being tested and implemented

use crate::connection::authentication::{verify_remote_auth_cert, ConnectionAuth};
use crate::connection::handshake;
use crate::connection::{Error as ConnectionError, Error};
use crate::{create_auth_cert, create_receiving_mac_key, create_sending_mac_key, gen_shared_key};
use hmac::Hmac;
use std::time::{SystemTime, UNIX_EPOCH};
use substrate_stellar_sdk::types::{
    AuthCert, AuthenticatedMessage, AuthenticatedMessageV0, Curve25519Public, Hello, HmacSha256Mac,
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
    pub sending_mac_key: Option<HmacSha256Mac>,
    pub receiving_mac_key: Option<HmacSha256Mac>,
    connection_auth: ConnectionAuth,
    remote_called_us: bool,
}

impl Connection {
    pub fn new(
        local_node: NodeInfo,
        keypair: SecretKey,
        auth_cert_expiration: u64,
        remote_called_us: bool,
    ) -> Connection {
        let connection_auth =
            ConnectionAuth::new(&local_node.network_id, keypair, auth_cert_expiration);

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
            receiving_mac_key: None,
            connection_auth,
            remote_called_us,
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

                create_sha256_hmac(&buffer, &key.mac)
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

    pub fn handle_message(&mut self, msg: StellarMessage) -> Result<(), Error> {
        match msg {
            StellarMessage::ErrorMsg(_) => {}
            StellarMessage::Hello(hello) => {
                return self.process_hello_message(hello);
            }
            StellarMessage::Auth(_) => {}
            StellarMessage::DontHave(_) => {}
            StellarMessage::GetPeers => {}
            StellarMessage::Peers(_) => {}
            StellarMessage::GetTxSet(_) => {}
            StellarMessage::TxSet(_) => {}
            StellarMessage::Transaction(_) => {}
            StellarMessage::SurveyRequest(_) => {}
            StellarMessage::SurveyResponse(_) => {}
            StellarMessage::GetScpQuorumset(_) => {}
            StellarMessage::ScpQuorumset(_) => {}
            StellarMessage::ScpMessage(_) => {}
            StellarMessage::GetScpState(_) => {}
            StellarMessage::SendMore(_) => {}
        }

        Ok(())
    }

    fn _create_hello_message(&mut self, valid_at: u64) -> StellarMessage {
        let auth_cert = match self.connection_auth.auth_cert(valid_at) {
            Ok(auth_cert) => auth_cert.clone(),
            Err(_) => {
                // depending on the error, let's create a new one.
                let new_auth_cert = create_auth_cert(
                    self.connection_auth.network_id(),
                    self.connection_auth.keypair(),
                    valid_at,
                    self.connection_auth.pub_key_ecdh().clone(),
                );

                self.connection_auth.set_auth_cert(new_auth_cert.clone());

                new_auth_cert
            }
        };

        let peer_id = self.connection_auth.keypair().get_public();

        handshake::create_hello_message(
            peer_id.clone(),
            self.local_nonce,
            auth_cert,
            self.local_listening_port,
            &self.local_node,
        )
    }

    pub fn create_hello_message(&mut self) -> StellarMessage {
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let time_now = u64::try_from(time_now).unwrap();

        self._create_hello_message(time_now)
    }

    fn update_remote_info(&mut self, hello: &Hello) {
        self.remote_nonce = Some(hello.nonce);
        self.remote_pub_key_ecdh = Some(hello.cert.pubkey.clone());
        self.remote_pub_key = Some(hello.peer_id.clone());
        self.remote_node = Some(NodeInfo {
            ledger_version: hello.ledger_version,
            overlay_version: hello.overlay_version,
            overlay_min_version: hello.overlay_min_version,
            version_str: hello.version_str.get_vec().clone(),
            network_id: hello.network_id,
        });
    }

    fn set_sending_mac_key(&mut self) -> Result<(), Error> {
        let shared_key = self.prepare_shared_key()?;

        self.sending_mac_key = Some(create_sending_mac_key(
            &shared_key,
            self.local_nonce,
            self.remote_nonce
                .ok_or(Error::Undefined("remote_nonce".to_owned()))?,
            !self.remote_called_us,
        ));

        Ok(())
    }

    fn set_receiving_mac_key(&mut self) -> Result<(), Error> {
        let shared_key = self.prepare_shared_key()?;
        self.receiving_mac_key = Some(create_receiving_mac_key(
            &shared_key,
            self.local_nonce,
            self.remote_nonce
                .ok_or(Error::Undefined("remote_nonce".to_owned()))?,
            !self.remote_called_us,
        ));

        Ok(())
    }

    fn prepare_shared_key(&mut self) -> Result<HmacSha256Mac, Error> {
        let remote_pub_key_ecdh = self
            .remote_pub_key_ecdh
            .as_ref()
            .ok_or(Error::Undefined("remote_pub_key_ecdh".to_owned()))?;

        let shared_key = match self
            .connection_auth
            .shared_key(remote_pub_key_ecdh, !self.remote_called_us)
        {
            None => {
                let new_shared_key = gen_shared_key(
                    remote_pub_key_ecdh,
                    self.connection_auth.secret_key_ecdh(),
                    self.connection_auth.pub_key_ecdh(),
                    !self.remote_called_us,
                );

                self.connection_auth.set_shared_key(
                    remote_pub_key_ecdh,
                    new_shared_key.clone(),
                    !self.remote_called_us,
                );

                new_shared_key
            }

            Some(shared_key) => shared_key.clone(),
        };

        Ok(shared_key)
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

        self.update_remote_info(&hello);
        self.set_sending_mac_key()?;
        self.set_receiving_mac_key()?;

        Ok(())
    }
}
