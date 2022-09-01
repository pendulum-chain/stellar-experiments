use std::time::{SystemTime, UNIX_EPOCH};

use substrate_stellar_sdk::{PublicKey, SecretKey, XdrCodec};
use substrate_stellar_sdk::types::{AuthenticatedMessage, AuthenticatedMessageV0, Curve25519Public, Hello, HmacSha256Mac, MessageType, SendMore, StellarMessage, Uint256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use crate::connection::{Error, handshake};
use crate::{ConnectionAuth, create_auth_cert, create_auth_message, create_receiving_mac_key, create_sending_mac_key, gen_shared_key, get_message_length, HandshakeState, NodeInfo, parse_authenticated_message, verify_remote_auth_cert, xdr_converter};

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::SendError;
use crate::helper::{create_sha256_hmac, generate_random_nonce, verify_hmac};

pub struct ConnectionConfig {
    local_sequence: u64,
    local_nonce: Uint256,
    local_node: NodeInfo,
    local_listening_port: u32,

    remote_sequence: u64,
    remote_pub_key_ecdh: Option<Curve25519Public>,
    remote_pub_key: Option<PublicKey>,
    remote_nonce: Option<Uint256>,
    remote_node: Option<NodeInfo>,
    sending_mac_key: Option<HmacSha256Mac>,
    receiving_mac_key: Option<HmacSha256Mac>,
    connection_auth: ConnectionAuth,

    remote_called_us: bool,
    receiveTransactionMessages: bool,
    receiveSCPMessages: bool
}

impl ConnectionConfig {
    pub fn new(
        local_node: NodeInfo,
        keypair: SecretKey,
        auth_cert_expiration: u64,
        remote_called_us: bool
    ) -> Self {
        let connection_auth =
            ConnectionAuth::new(&local_node.network_id, keypair, auth_cert_expiration);
        
        ConnectionConfig{
            local_sequence: 0,
            local_nonce: generate_random_nonce(),
            local_node,
            local_listening_port: 11625,
            remote_sequence: 0,
            remote_pub_key_ecdh: None,
            remote_pub_key: None,
            remote_nonce: None,
            remote_node: None,
            sending_mac_key: None,
            receiving_mac_key: None,
            connection_auth,
            remote_called_us,
            receiveTransactionMessages: false,
            receiveSCPMessages: true
        }
    }

    fn process_hello_message(&mut self, hello: &Hello) -> Result<(), Error> {
        println!("processing hello message...");
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let time_now = u64::try_from(time_now).unwrap();

        let mut network_id = self.connection_auth.network_id().to_xdr();
        if !verify_remote_auth_cert(time_now, &hello.peer_id, &hello.cert, &mut network_id) {
            return Err(Error::AuthCertInvalid);
        }

        self.update_remote_info(hello);
        self.set_sending_mac_key()?;
        self.set_receiving_mac_key()?;

        Ok(())
    }

    fn _create_hello_message(&mut self) -> StellarMessage {
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let time_now = u64::try_from(time_now).unwrap();

        
        let auth_cert = match self.connection_auth.auth_cert(time_now) {
            Ok(auth_cert) => auth_cert.clone(),
            Err(_) => {
                println!("creating new auth cert");
                // depending on the error, let's create a new one.
                let new_auth_cert = create_auth_cert(
                    self.connection_auth.network_id(),
                    self.connection_auth.keypair(),
                    time_now,
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

    pub fn create_hello_message(&mut self) -> Result<Vec<u8>, Error> {
        let hello = self._create_hello_message();
        let a_hello = self.authenticate_message(hello);
        xdr_converter::from_authenticated_message(&a_hello)
            .map_err(|e| e.into())
    }

    pub fn create_auth_message(&mut self) -> Result<Vec<u8>, Error>  {
        let auth = handshake::create_auth_message();
        let a_hello = self.authenticate_message(auth);
        xdr_converter::from_authenticated_message(&a_hello)
            .map_err(|e| e.into())
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

    /// Returns HmacSha256Mac
    fn mac_for_auth_message(&self, message: &StellarMessage) -> HmacSha256Mac {
        let empty = HmacSha256Mac { mac: [0; 32] };

        if self.remote_pub_key_ecdh.is_none() || self.sending_mac_key.is_none() {
            return empty;
        }

        let mac_key = self.sending_mac_key.as_ref().unwrap_or(&empty);

        let mut buffer = self.local_sequence.to_be_bytes().to_vec();
        buffer.append(&mut message.to_xdr());
        create_sha256_hmac(&buffer, &mac_key.mac)
    }

    pub fn authenticate_message(&mut self, message: StellarMessage) -> AuthenticatedMessage {
        let mac = self.mac_for_auth_message(&message);
        let sequence = self.local_sequence;

        match &message {
            StellarMessage::ErrorMsg(_) | StellarMessage::Hello(_) => {}
            _ => {
                self.local_sequence +=1;
            },
        }

        let auth_message_v0 = AuthenticatedMessageV0 {
            sequence,
            message,
            mac,
        };

        AuthenticatedMessage::V0(auth_message_v0)
    }

    pub fn filter_reply(&mut self, data: &[u8]) -> Result<Option<StellarMessage>,Error> {
        let (auth_msg, msg_type) = parse_authenticated_message(data)?;
        println!("process_next_message: MessageType: {:?} remote_seq: {:?}",msg_type, self.remote_sequence);
        match msg_type {
            MessageType::Transaction if !self.receiveTransactionMessages => {
                self.remote_sequence +=1;
                // send more?
                Ok(None)
            }
            MessageType::ScpMessage if !self.receiveSCPMessages => {
                self.remote_sequence +=1;
                Ok(None)
            }
            MessageType::Hello => {
                if let StellarMessage::Hello(hello) = &auth_msg.message {
                    self.process_hello_message(hello)?;
                    Ok(Some(auth_msg.message))

                } else {
                    return Err(Error::Undefined("Expecting a Hello Message".to_string()));
                }
            }
            _ => {
                // todo: verify auth only if hello has been received.
                self.verify_auth(&auth_msg, &data[4..(data.len() - 32)])?;
                self.remote_sequence +=1;
                Ok(Some(auth_msg.message))
            }
        }

    }

    fn verify_auth(&self, auth_msg: &AuthenticatedMessageV0, body:&[u8]) -> Result<(),Error> {
        println!("remote sequence: {:?}, auth sequence: {:?}", self.remote_sequence, auth_msg.sequence);
        if self.remote_sequence != auth_msg.sequence {
            //must be handled on main thread because workers could mix up order of messages.
            return Err(Error::InvalidSequenceNumber);
        }

        if let Some(recv_mac_key) = &self.receiving_mac_key {
            verify_hmac(body,&recv_mac_key.mac, &auth_msg.mac.to_xdr())
                .map_err(|_| Error::InvalidHmac)?;
        }

        println!("auth verified!");
        Ok(())
    }
}
