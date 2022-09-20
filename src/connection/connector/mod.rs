mod message_handler;
mod message_sender;

use crate::authentication::{create_auth_cert, gen_shared_key, ConnectionAuth};
use crate::connection::flow_controller::FlowController;
use crate::connection::hmac::{create_sha256_hmac, verify_hmac, HMacKeys};
use crate::connection::{handshake, Xdr};
use crate::node::{LocalInfo, NodeInfo, RemoteInfo};
use crate::Error;
use crate::{xdr_converter, ConnConfig, ConnectionState, HandshakeState};
use substrate_stellar_sdk::types::{
    AuthenticatedMessage, AuthenticatedMessageV0, Curve25519Public, HmacSha256Mac, StellarMessage,
};
use substrate_stellar_sdk::XdrCodec;
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum ConnectorActions {
    SendHello,
    SendMessage(StellarMessage),
    HandleMessage(Xdr),
}

pub struct Connector {
    local: LocalInfo,

    remote: Option<RemoteInfo>,
    hmac_keys: Option<HMacKeys>,

    connection_auth: ConnectionAuth,

    remote_called_us: bool,
    receive_tx_messages: bool,
    receive_scp_messages: bool,

    handshake_state: HandshakeState,
    flow_controller: FlowController,

    /// a channel to writing xdr messages to stream.
    stream_writer: mpsc::Sender<ConnectorActions>,

    /// a channel to communicate back to the caller
    stellar_message_writer: mpsc::Sender<ConnectionState>,
}

impl Connector {
    /// Wraps the stellar message with `AuthenticatedMessage`
    fn authenticate_message(&mut self, message: StellarMessage) -> AuthenticatedMessage {
        let mac = self.mac_for_auth_message(&message);
        let sequence = self.local.sequence();

        match &message {
            StellarMessage::ErrorMsg(_) | StellarMessage::Hello(_) => {}
            _ => {
                self.local.increment_sequence();
            }
        }

        let auth_message_v0 = AuthenticatedMessageV0 {
            sequence,
            message,
            mac,
        };

        AuthenticatedMessage::V0(auth_message_v0)
    }

    pub fn create_xdr_message(&mut self, msg: StellarMessage) -> Result<Vec<u8>, Error> {
        let auth_msg = self.authenticate_message(msg);
        xdr_converter::from_authenticated_message(&auth_msg).map_err(Error::from)
    }

    /// Returns HmacSha256Mac for the AuthenticatedMessage
    fn mac_for_auth_message(&self, message: &StellarMessage) -> HmacSha256Mac {
        let empty = HmacSha256Mac { mac: [0; 32] };

        if self.remote.is_none() || self.hmac_keys.is_none() {
            return empty;
        }

        let sending_mac_key = self
            .hmac_keys
            .as_ref()
            .map(|keys| keys.sending().mac)
            .unwrap_or([0; 32]);

        let mut buffer = self.local.sequence().to_be_bytes().to_vec();
        buffer.append(&mut message.to_xdr());
        create_sha256_hmac(&buffer, &sending_mac_key).unwrap_or(empty)
    }

    /// Verifies the AuthenticatedMessage, received from the Stellar Node
    fn verify_auth(&self, auth_msg: &AuthenticatedMessageV0, body: &[u8]) -> Result<(), Error> {
        let remote = self.remote.as_ref().ok_or(Error::NoRemoteInfo)?;
        log::debug!(
            "remote sequence: {}, auth message sequence: {}",
            remote.sequence(),
            auth_msg.sequence
        );
        if remote.sequence() != auth_msg.sequence {
            //must be handled on main thread because workers could mix up order of messages.
            return Err(Error::InvalidSequenceNumber);
        }

        let keys = self.hmac_keys.as_ref().ok_or(Error::MissingHmacKeys)?;
        verify_hmac(body, &keys.receiving().mac, &auth_msg.mac.to_xdr())?;

        Ok(())
    }

    fn get_shared_key(&mut self, remote_pub_key_ecdh: &Curve25519Public) -> HmacSha256Mac {
        match self
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
        }
    }

    /// The hello message is dependent on the auth cert
    pub fn create_hello_message(&mut self, valid_at: u64) -> Result<Vec<u8>, Error> {
        let auth_cert = match self.connection_auth.auth_cert(valid_at) {
            Ok(auth_cert) => auth_cert.clone(),
            Err(_) => {
                // depending on the error, let's create a new one.
                let new_auth_cert = create_auth_cert(
                    self.connection_auth.network_id(),
                    self.connection_auth.keypair(),
                    valid_at,
                    self.connection_auth.pub_key_ecdh().clone(),
                )?;

                self.connection_auth.set_auth_cert(new_auth_cert.clone());

                new_auth_cert
            }
        };

        let peer_id = self.connection_auth.keypair().get_public();

        let msg = handshake::create_hello_message(
            peer_id.clone(),
            self.local.nonce(),
            auth_cert,
            self.local.port(),
            &self.local.node(),
        )?;

        self.create_xdr_message(msg)
    }

    pub fn new(
        local_node: NodeInfo,
        cfg: ConnConfig,
        send_to_self: mpsc::Sender<ConnectorActions>,
        send_to_user: mpsc::Sender<ConnectionState>,
    ) -> Self {
        let connection_auth = ConnectionAuth::new(
            &local_node.network_id,
            cfg.keypair(),
            cfg.auth_cert_expiration,
        );

        Connector {
            local: LocalInfo::new(local_node),
            remote: None,
            hmac_keys: None,
            connection_auth,
            remote_called_us: cfg.remote_called_us,
            receive_tx_messages: cfg.recv_scp_messages,
            receive_scp_messages: cfg.recv_scp_messages,
            handshake_state: HandshakeState::Connecting,
            flow_controller: FlowController::default(),
            stream_writer: send_to_self,
            stellar_message_writer: send_to_user,
        }
    }
}
