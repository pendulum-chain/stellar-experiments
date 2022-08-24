#![allow(dead_code)] //todo: remove after being tested and implemented

use std::io::{Read, Write};
use std::net::TcpStream;
use crate::connection::authentication::{verify_remote_auth_cert, ConnectionAuth};
use crate::connection::handshake;
use crate::connection::{Error as ConnectionError, Error};
use crate::{create_auth_cert, create_auth_message, create_receiving_mac_key, create_sending_mac_key, gen_shared_key, get_message_length, HandshakeState, parse_authenticated_message, ReadState, xdr_converter};
use hmac::Hmac;
use std::time::{SystemTime, UNIX_EPOCH};
use substrate_stellar_sdk::types::{AuthCert, AuthenticatedMessage, AuthenticatedMessageV0, Curve25519Public, Hello, HmacSha256Mac, SendMore, StellarMessage, Uint256};
use substrate_stellar_sdk::{PublicKey, SecretKey, XdrCodec};

use crate::helper::{create_sha256_hmac, generate_random_nonce};
use crate::node::NodeInfo;


// state machine? or actor?
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
    stream: TcpStream,
    
    
    
    read_state:ReadState,
    handshake_state: HandshakeState
}

impl Connection {
    pub fn new(
        local_node: NodeInfo,
        keypair: SecretKey,
        auth_cert_expiration: u64,
        remote_called_us: bool,
        address:&str
    ) -> Result<Self,Error> {
        let mut stream  = TcpStream::connect(address).map_err(|e| {
            Error::ConnectionFailed(e.to_string())
        })?;

        let connection_auth =
            ConnectionAuth::new(&local_node.network_id, keypair, auth_cert_expiration);

        Ok(Connection {
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
            stream,
            read_state: ReadState::ReadNotStarted,
            handshake_state: HandshakeState::Connecting
        })
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
    fn authenticate_message(&mut self, message: StellarMessage) -> AuthenticatedMessage {
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

    pub fn send_stellar_message(&mut self, msg:StellarMessage) -> Result<(),Error> {
        let authenticated_msg = self.authenticate_message(msg);
        let xdr_authenticated_msg = xdr_converter::from_authenticated_message(&authenticated_msg)?;

        let write_size = self.stream.write(&xdr_authenticated_msg).map_err(|e| {
            Error::WriteFailed(e.to_string())
        })?;
        println!("writing message with size {:?}", write_size);

        Ok(())

    }


    fn read_response(&mut self) -> Result<(),Error> {
        let mut readbuf = [0;1024];

        let mut read_size = self.stream.read(&mut readbuf).map_err(|e| Error::ReadFailed(e.to_string()))?;
        loop {
            // If size bytes are not available to be read, null will be returned unless
            // the stream has ended, in which case all of the data
            // remaining in the internal buffer will be returned.
            if self.read_state == ReadState::ReadNotStarted && read_size > 0 {
                let message_len = get_message_length(&readbuf);
                let message_len = usize::try_from(message_len).unwrap();

                if message_len > readbuf.len() {
                    return Err(Error::ReadFailed("Not enough buffer".to_string()));
                }
                self.read_state = ReadState::ReadyForMessage;

                let data = &readbuf[4..message_len + 4];
                let data = parse_authenticated_message(data)?;

                if self.handshake_state >= HandshakeState::GotHello {
                    //todo: verify authentication
                }

                self.handle_message(data.message)?;

                println!("  READ-SIZE: {}, message-len: {}", read_size, message_len);
                read_size = read_size.saturating_sub(message_len + 4);

            } else {
                break;
            }
        }
        Ok(())
    }

    // todo: time out if response is taking too much time
    pub fn process_next_message(&mut self) -> Result<(),Error> {
        let mut readbuf = [0;1024];

        let mut read_size = self.stream.read(&mut readbuf).map_err(|e| Error::ReadFailed(e.to_string()))?;
        loop {
            // If size bytes are not available to be read, null will be returned unless
            // the stream has ended, in which case all of the data
            // remaining in the internal buffer will be returned.
            if self.read_state == ReadState::ReadNotStarted && read_size > 0 {
                let message_len = get_message_length(&readbuf);
                let message_len = usize::try_from(message_len).unwrap();

                if message_len > readbuf.len() {
                    return Err(Error::ReadFailed("Not enough buffer".to_string()));
                }
                self.read_state = ReadState::ReadyForMessage;
                println!("update read_state to ReadyForMessage");

                let data = &readbuf[4..message_len + 4];
                let data = parse_authenticated_message(data)?;

                if self.handshake_state >= HandshakeState::GotHello {
                    //todo: verify authentication
                    println!("todo: verify authentication");
                }

                self.handle_message(data.message)?;

                println!("  READ-SIZE: {}, message-len: {}", read_size, message_len);
                read_size = read_size.saturating_sub(message_len + 4);

            } else {
                break;
            }
        }

        // response consumed already
        Ok(())
    }

    fn complete_handshake(&mut self) -> Result<(),Error> {
        if self.remote_called_us {
            self.send_auth_message()?;
        }

        self.handshake_state =HandshakeState::Completed;
        println!("updated handshake_state to Completed ");
        self.send_sendMore_message()
    }

    // returns empty when handling was successful
    fn handle_message(&mut self, msg: StellarMessage) -> Result<(), Error> {
        match msg {
            StellarMessage::ErrorMsg(_) => {}
            StellarMessage::Hello(hello) => {
                self.process_hello_message(hello)?;

                if self.remote_called_us {
                    self.send_hello_message()?;
                } else {
                    self.send_auth_message()?;
                    println!("Auth message sent");
                }
                println!("Done sending hello message.");
                println!("update handshake_state to GotHello");
                self.handshake_state = HandshakeState::GotHello;
            }
            StellarMessage::Auth(_) => {
                self.complete_handshake()?
            }
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
            StellarMessage::GetScpState(state) => {
                println!("todo: handle GetScpState");
            }
            StellarMessage::SendMore(x) => {
                println!("todo: handle SendMore");
            }
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

    pub fn send_hello_message(&mut self) -> Result<(),Error> {
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let time_now = u64::try_from(time_now).unwrap();

        let hello = self._create_hello_message(time_now);
        self.send_stellar_message(hello)?;

        // should receive a response immediately
        self.process_next_message()
    }

    fn send_auth_message(&mut self) -> Result<(),Error> {
        println!("SENDING AUTH MESSAGE: ");
        let msg = create_auth_message();
        self.send_stellar_message(msg)?;
        self.process_next_message()
    }

    fn send_sendMore_message(&mut self) -> Result<(),Error> {
        println!("SENDING SENDMORE MESSAGE");
        let msg = StellarMessage::SendMore(SendMore{ num_messages: 0 });
        self.send_stellar_message(msg)?;
        self.process_next_message()
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
