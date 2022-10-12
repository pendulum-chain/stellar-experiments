use crate::connection::authentication::{gen_shared_key, ConnectionAuth};
use crate::connection::flow_controller::FlowController;
use crate::connection::hmac::{verify_hmac, HMacKeys};
use crate::handshake::HandshakeState;
use crate::{ConnConfig, ConnectionError, ConnectorActions, StellarNodeMessage};
use substrate_stellar_sdk::types::{
    AuthenticatedMessageV0, Curve25519Public, HmacSha256Mac, MessageType,
};
use substrate_stellar_sdk::XdrCodec;
use tokio::sync::mpsc;
use tokio::time;

use crate::node::{LocalInfo, NodeInfo, RemoteInfo};

pub struct Connector {
    local: LocalInfo,

    remote: Option<RemoteInfo>,
    hmac_keys: Option<HMacKeys>,

    pub(crate) connection_auth: ConnectionAuth,
    pub(crate) timeout_in_secs: u64,
    pub(crate) retries:u8,

    remote_called_us: bool,
    receive_tx_messages: bool,
    receive_scp_messages: bool,

    handshake_state: HandshakeState,
    flow_controller: FlowController,

    /// a channel to writing xdr messages to stream.
    stream_writer: mpsc::Sender<ConnectorActions>,

    /// a channel to communicate back to the caller
    stellar_message_writer: mpsc::Sender<StellarNodeMessage>,
}

impl Connector {
    /// Verifies the AuthenticatedMessage, received from the Stellar Node
    pub(crate) fn verify_auth(
        &self,
        auth_msg: &AuthenticatedMessageV0,
        body: &[u8],
    ) -> Result<(), ConnectionError> {
        let remote = self.remote.as_ref().ok_or(ConnectionError::NoRemoteInfo)?;
        log::debug!(
            "remote sequence: {}, auth message sequence: {}",
            remote.sequence(),
            auth_msg.sequence
        );
        if remote.sequence() != auth_msg.sequence {
            //must be handled on main thread because workers could mix up order of messages.
            return Err(ConnectionError::InvalidSequenceNumber);
        }

        let keys = self
            .hmac_keys
            .as_ref()
            .ok_or(ConnectionError::MissingHmacKeys)?;
        verify_hmac(body, &keys.receiving().mac, &auth_msg.mac.to_xdr())?;

        Ok(())
    }

    pub fn get_shared_key(&mut self, remote_pub_key_ecdh: &Curve25519Public) -> HmacSha256Mac {
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

    pub fn new(
        local_node: NodeInfo,
        cfg: ConnConfig,
        send_to_self: mpsc::Sender<ConnectorActions>,
        send_to_user: mpsc::Sender<StellarNodeMessage>,
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
            timeout_in_secs: cfg.timeout_in_secs,
            retries: cfg.retries,
            remote_called_us: cfg.remote_called_us,
            receive_tx_messages: cfg.recv_scp_messages,
            receive_scp_messages: cfg.recv_scp_messages,
            handshake_state: HandshakeState::Connecting,
            flow_controller: FlowController::default(),
            stream_writer: send_to_self,
            stellar_message_writer: send_to_user,
        }
    }

    pub fn local(&self) -> &LocalInfo {
        &self.local
    }

    pub fn local_sequence(&self) -> u64 {
        self.local.sequence()
    }

    pub fn increment_local_sequence(&mut self) {
        self.local.increment_sequence();
    }

    pub fn remote(&self) -> Option<&RemoteInfo> {
        self.remote.as_ref()
    }

    pub fn set_remote(&mut self, value: RemoteInfo) {
        self.remote = Some(value);
    }

    pub fn increment_remote_sequence(&mut self) -> Result<(), ConnectionError> {
        self.remote
            .as_mut()
            .map(|remote| remote.increment_sequence())
            .ok_or(ConnectionError::NoRemoteInfo)
    }

    pub fn hmac_keys(&self) -> Option<&HMacKeys> {
        self.hmac_keys.as_ref()
    }

    pub fn set_hmac_keys(&mut self, value: HMacKeys) {
        self.hmac_keys = Some(value);
    }

    // Connection Auth

    pub fn remote_called_us(&self) -> bool {
        self.remote_called_us
    }

    pub fn receive_tx_messages(&self) -> bool {
        self.receive_tx_messages
    }

    pub fn receive_scp_messages(&self) -> bool {
        self.receive_scp_messages
    }

    pub fn is_handshake_created(&self) -> bool {
        self.handshake_state >= HandshakeState::GotHello
    }

    pub fn got_hello(&mut self) {
        self.handshake_state = HandshakeState::GotHello;
    }

    pub fn handshake_completed(&mut self) {
        self.handshake_state = HandshakeState::Completed;
    }

    pub async fn send_to_user(&self, msg: StellarNodeMessage) -> Result<(), ConnectionError> {
        self.stellar_message_writer
            .send(msg)
            .await
            .map_err(ConnectionError::from)
    }

    pub async fn send_to_node(&self, action: ConnectorActions) -> Result<(), ConnectionError> {
        self.stream_writer
            .send(action)
            .await
            .map_err(ConnectionError::from)
    }

    pub fn inner_check_to_send_more(&mut self, msg_type: MessageType) -> bool {
        self.flow_controller.send_more(msg_type)
    }
    pub fn enable_flow_controller(
        &mut self,
        local_overlay_version: u32,
        remote_overlay_version: u32,
    ) {
        self.flow_controller
            .enable(local_overlay_version, remote_overlay_version)
    }
}
