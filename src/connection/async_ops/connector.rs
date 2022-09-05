use crate::async_ops::Xdr;
use crate::connection::{handshake, Error};
use crate::helper::{create_sha256_hmac, generate_random_nonce, verify_hmac};
use crate::{
    create_auth_cert, create_auth_message, create_receiving_mac_key, create_sending_mac_key,
    gen_shared_key, parse_authenticated_message, verify_remote_auth_cert, xdr_converter,
    Connection, ConnectionAuth, HandshakeState, NodeInfo,
};
use std::time::{SystemTime, UNIX_EPOCH};
use substrate_stellar_sdk::types::{AuthenticatedMessage, AuthenticatedMessageV0, Curve25519Public, Hello, HmacSha256Mac, MessageType, SendMore, StellarMessage, Uint256};
use substrate_stellar_sdk::{PublicKey, SecretKey, XdrCodec};
use tokio::sync::{mpsc, oneshot};
use crate::async_ops::flow_controller::{FlowController, MAX_FLOOD_MSG_CAP};

#[derive(Debug)]
pub enum ConnectorActions {
    SendHello,
    SendMessage(StellarMessage),
    HandleMessage(Xdr),
}

#[derive(Debug)]
pub enum ConnectionState {
    Connect{
        pub_key:PublicKey,
        node_info:NodeInfo
    },
    Data(StellarMessage),
    Error(String),
    Timeout
}


pub struct Connector {
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
    receive_tx_messages: bool,
    receive_scp_messages: bool,

    handshake_state: HandshakeState,
    flow_controller: FlowController,

    /// a channel to writing xdr messages to stream.
    stream_writer: Option<mpsc::Sender<Xdr>>,

    /// a channel to communicate back to the caller
    stellar_message_writer: Option<mpsc::Sender<ConnectionState>>,
}

impl Connector {
    /// Sends an xdr version of a wrapped AuthenticatedMessage ( StellarMessage ).
    async fn send_stellar_message(&mut self, msg: StellarMessage) -> Result<(), Error> {
        // wraps the StellarMessage with AuthenticatedMessage and get the xdr format.
        let auth_msg = self.authenticate_message(msg);
        let xdr_msg = xdr_converter::from_authenticated_message(&auth_msg)?;

        let sender = self.stream_writer.as_ref().ok_or(Error::ChannelNotSet)?;
        sender.send(xdr_msg).await.map_err(Error::from)
    }

    /// Wraps the stellar message with `AuthenticatedMessage`
    fn authenticate_message(&mut self, message: StellarMessage) -> AuthenticatedMessage {
        let mac = self.mac_for_auth_message(&message);
        let sequence = self.local_sequence;

        match &message {
            StellarMessage::ErrorMsg(_) | StellarMessage::Hello(_) => {}
            _ => {
                self.local_sequence += 1;
            }
        }

        let auth_message_v0 = AuthenticatedMessageV0 {
            sequence,
            message,
            mac,
        };

        AuthenticatedMessage::V0(auth_message_v0)
    }

    /// Returns HmacSha256Mac for the AuthenticatedMessage
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

    /// Processes the raw bytes from the stream
    async fn process_raw_message(&mut self, data: &[u8]) -> Result<(), Error> {
        let (auth_msg, msg_type) = parse_authenticated_message(data)?;
        // println!(
        //     "process_raw_message: MessageType: {:?} remote_seq: {:?}",
        //     msg_type, self.remote_sequence
        // );

        match msg_type {
            MessageType::Transaction if !self.receive_tx_messages => {
                self.remote_sequence += 1;
                self.check_to_send_more(msg_type).await?;
            }

            MessageType::ScpMessage if !self.receive_scp_messages => {
                self.remote_sequence += 1;
            }

            _ => {
                // we only verify the authenticated message when a handshake has been done.
                if self.handshake_state >= HandshakeState::GotHello {
                    self.verify_auth(&auth_msg, &data[4..(data.len() - 32)])?;
                    self.remote_sequence += 1;
                }
                self.process_stellar_message(auth_msg.message, msg_type).await?;
            }
        }
        Ok(())
    }

    /// Handles what to do next with the message. Mostly it will be sent back to the user
    async fn process_stellar_message(&mut self, msg: StellarMessage, msg_type:MessageType) -> Result<(), Error> {
        match msg {
            StellarMessage::ErrorMsg(_) => {}
            StellarMessage::Hello(hello) => {
                // update the node info based on the hello message
                self.process_hello_message(hello)?;

                self.handshake_state = HandshakeState::GotHello;

                if self.remote_called_us {
                    self.send_hello_message().await?;
                } else {
                    self.send_auth_message().await?;
                }
                println!("Done sending hello message.");
            }

            StellarMessage::Auth(_) => {
                self.process_auth_message().await?;
            }

            StellarMessage::SendMore(x) => {
                // todo: what to do with send more?
                println!("what to do with send more");
            }
            other => {
                let sender = self
                    .stellar_message_writer
                    .as_ref()
                    .ok_or(Error::ChannelNotSet)?;
                sender.send(ConnectionState::Data(other)).await?;
                self.check_to_send_more(msg_type).await?;
            }
        }
        Ok(())
    }

    async fn check_to_send_more(&mut self, message_type:MessageType) -> Result<(),Error> {
        if !self.flow_controller.send_more(message_type) {
            return Ok(());
        }

        println!("\n----------- SENDING SENDMORE MESSAGE: -------------");

        let msg =  StellarMessage::SendMore(SendMore {
            num_messages: MAX_FLOOD_MSG_CAP
        });

        self.send_stellar_message(msg).await
    }

    async fn process_auth_message(&mut self) -> Result<(),Error> {
        if self.remote_called_us {
            self.send_auth_message().await?;
        }

        self.handshake_state = HandshakeState::Completed;
        let sender = self
            .stellar_message_writer
            .as_ref()
            .ok_or(Error::ChannelNotSet)?;

        println!("Handshake completed!!");
        sender.send(ConnectionState::Connect {
            pub_key: self.remote_pub_key.as_ref().unwrap().clone(),
            node_info: self.remote_node.as_ref().unwrap().clone()
        }).await?;

        let remote_node_info = self.remote_node.as_ref()
            .ok_or(Error::Undefined("No remote overlay version after handshake".to_string()))?;

        self.flow_controller.check_set_enabled(
            self.local_node.overlay_version,
            remote_node_info.overlay_version
        );

        self.check_to_send_more(MessageType::Auth).await
    }

    /// Updates the config based on the hello message that was received from the Stellar Node
    fn process_hello_message(&mut self, hello: Hello) -> Result<(), Error> {
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let time_now = u64::try_from(time_now).unwrap();

        let mut network_id = self.connection_auth.network_id().to_xdr();

        if !verify_remote_auth_cert(time_now, &hello.peer_id, &hello.cert, &mut network_id) {
            return Err(Error::AuthCertInvalid);
        }

        self.update_remote_info(&hello);
        self.set_sending_mac_key()?;
        self.set_receiving_mac_key()?;

        Ok(())
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
                // generate a new one when there's none.
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

    /// Verifies the AuthenticatedMessage, received from the Stellar Node
    fn verify_auth(&self, auth_msg: &AuthenticatedMessageV0, body: &[u8]) -> Result<(), Error> {
        println!(
            "remote sequence: {:?}, auth sequence: {:?}",
            self.remote_sequence, auth_msg.sequence
        );
        if self.remote_sequence != auth_msg.sequence {
            //must be handled on main thread because workers could mix up order of messages.
            return Err(Error::InvalidSequenceNumber);
        }

        if let Some(recv_mac_key) = &self.receiving_mac_key {
            verify_hmac(body, &recv_mac_key.mac, &auth_msg.mac.to_xdr())
                .map_err(|_| Error::InvalidHmac)?;
        }
        Ok(())
    }

    /// The hello message is dependent on the auth cert
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

    async fn send_hello_message(&mut self) -> Result<(), Error> {
        println!("\n----------- SENDING HELLO MESSAGE: -------------");
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let time_now = u64::try_from(time_now).unwrap();

        let hello = self._create_hello_message(time_now);
        self.send_stellar_message(hello).await
    }

    async fn send_auth_message(&mut self) -> Result<(), Error> {
        println!("\n----------- SENDING AUTH MESSAGE: -------------");
        let msg = create_auth_message();
        self.send_stellar_message(msg).await
    }

    pub fn new(
        local_node: NodeInfo,
        keypair: SecretKey,
        auth_cert_expiration: u64,
        remote_called_us: bool,
        // stream_writer: broadcast::Sender<Xdr>
    ) -> Self {
        let connection_auth =
            ConnectionAuth::new(&local_node.network_id, keypair, auth_cert_expiration);

        Connector {
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
            receive_tx_messages: false,
            receive_scp_messages: true,
            handshake_state: HandshakeState::Connecting,
            flow_controller: FlowController::default(),
            stream_writer: None,
            stellar_message_writer: None,
        }
    }

    pub fn set_stream_writer(&mut self, sender: mpsc::Sender<Xdr>) {
        self.stream_writer = Some(sender);
    }

    pub fn set_message_writer(&mut self, sender: mpsc::Sender<ConnectionState>) {
        self.stellar_message_writer = Some(sender);
    }
}


/// Where communication happens with the channels holding the stream.
pub async fn comm_service(
    mut cfg: Connector,
    mut receiver: mpsc::Receiver<ConnectorActions>,
) -> Result<(), Error> {
    loop {
        if let Some(actions) = receiver.recv().await {
            match actions {
                ConnectorActions::SendMessage(msg) => {
                    cfg.send_stellar_message(msg).await?;
                }
                ConnectorActions::HandleMessage(xdr) => {
                    cfg.process_raw_message(&xdr).await?;
                }
                ConnectorActions::SendHello => {
                    cfg.send_hello_message().await?;
                }
            }
        }
    }
}
