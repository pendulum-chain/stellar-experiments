use crate::async_ops::{Connector, Xdr};
use crate::connection::hmac_keys::HMacKeys;
use crate::errors::Error;
use crate::helper::time_now;
use crate::node::RemoteInfo;
use crate::{
    parse_authenticated_message, verify_remote_auth_cert, ConnectionState, HandshakeState,
};
use substrate_stellar_sdk::types::{Hello, MessageType, StellarMessage};
use substrate_stellar_sdk::XdrCodec;

impl Connector {
    /// Processes the raw bytes from the stream
    pub(crate) async fn process_raw_message(&mut self, xdr: Xdr) -> Result<(), Error> {
        let (message_id, data) = xdr;
        // println!(
        //     "pid: {:?} process_raw_message:  remote_seq: {:?}",
        //     message_id, self.remote_sequence
        // );
        let (auth_msg, msg_type) = parse_authenticated_message(&data)?;

        match msg_type {
            MessageType::Transaction if !self.receive_tx_messages => {
                self.increment_remote_sequence()?;
                self.check_to_send_more(msg_type).await?;
            }

            MessageType::ScpMessage if !self.receive_scp_messages => {
                self.increment_remote_sequence()?;
            }

            _ => {
                // we only verify the authenticated message when a handshake has been done.
                if self.handshake_state >= HandshakeState::GotHello {
                    self.verify_auth(&auth_msg, &data[4..(data.len() - 32)])?;
                    self.increment_remote_sequence()?;
                }
                self.process_stellar_message(message_id, auth_msg.message, msg_type)
                    .await?;
            }
        }
        Ok(())
    }

    /// Handles what to do next with the message. Mostly it will be sent back to the user
    async fn process_stellar_message(
        &mut self,
        message_id: u32,
        msg: StellarMessage,
        msg_type: MessageType,
    ) -> Result<(), Error> {
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

            StellarMessage::SendMore(_) => {
                // todo: what to do with send more?
                println!("what to do with send more");
            }
            other => {
                let sender = self
                    .stellar_message_writer
                    .as_ref()
                    .ok_or(Error::ChannelNotSet)?;
                sender
                    .send(ConnectionState::Data(message_id, other))
                    .await?;
                self.check_to_send_more(msg_type).await?;
            }
        }
        Ok(())
    }

    async fn process_auth_message(&mut self) -> Result<(), Error> {
        if self.remote_called_us {
            self.send_auth_message().await?;
        }

        self.handshake_state = HandshakeState::Completed;
        let sender = self
            .stellar_message_writer
            .as_ref()
            .ok_or(Error::ChannelNotSet)?;

        println!("Handshake completed!!");
        if let Some(remote) = self.remote.as_ref() {
            sender
                .send(ConnectionState::Connect {
                    pub_key: remote.pub_key().clone(),
                    node_info: remote.node().clone(),
                })
                .await?;

            self.flow_controller.enable(
                self.local.node().overlay_version,
                remote.node().overlay_version,
            );
        } else {
            log::warn!("No remote overlay version after handshake.");
        }

        self.check_to_send_more(MessageType::Auth).await
    }

    /// Updates the config based on the hello message that was received from the Stellar Node
    fn process_hello_message(&mut self, hello: Hello) -> Result<(), Error> {
        let mut network_id = self.connection_auth.network_id().to_xdr();

        if !verify_remote_auth_cert(time_now(), &hello.peer_id, &hello.cert, &mut network_id) {
            return Err(Error::AuthCertInvalid);
        }

        let remote_info = RemoteInfo::new(&hello);
        let shared_key = self.prepare_shared_key(&remote_info.pub_key_ecdh())?;

        self.hmac_keys = Some(HMacKeys::new(
            &shared_key,
            self.local.nonce(),
            remote_info.nonce(),
            self.remote_called_us,
        ));

        self.remote = Some(remote_info);

        Ok(())
    }
}
