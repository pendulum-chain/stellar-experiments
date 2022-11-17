use crate::connection::connector::ConnectorActions;
use crate::node::NodeInfo;
use crate::StellarNodeMessage;
use crate::{
    connection_handler, create_stream, receiving_service, ConnConfig, ConnectionError, Connector,
};
use substrate_stellar_sdk::types::StellarMessage;
use tokio::sync::mpsc;

pub struct UserControls {
    /// This is when we want to send stellar messages
    tx: mpsc::Sender<ConnectorActions>,
    /// For receiving stellar messages
    rx: mpsc::Receiver<StellarNodeMessage>,
}

impl UserControls {
    pub(crate) fn new(
        tx: mpsc::Sender<ConnectorActions>,
        rx: mpsc::Receiver<StellarNodeMessage>,
    ) -> Self {
        UserControls { tx, rx }
    }

    pub async fn send(&self, message: StellarMessage) -> Result<(), ConnectionError> {
        self.tx
            .send(ConnectorActions::SendMessage(message))
            .await
            .map_err(ConnectionError::from)
    }

    /// Receives Stellar messages from the connection.
    pub async fn recv(&mut self) -> Option<StellarNodeMessage> {
        self.rx.recv().await
    }

    /// Triggers connection to the Stellar Node.
    /// Returns the UserControls for the user to send and receive Stellar messages.
    pub async fn connect(
        local_node: NodeInfo,
        cfg: ConnConfig,
    ) -> Result<UserControls, ConnectionError> {
        // split the stream for easy handling of read and write
        let (rd, wr) = create_stream(&cfg.address()).await?;

        // ------------------ prepare the channels

        // this is a channel to communicate with the connection/config (this needs renaming)
        let (actions_sender, actions_receiver) = mpsc::channel::<ConnectorActions>(1024);
        // this is a chanel to communicate with the user/caller.
        let (message_writer, message_receiver) = mpsc::channel::<StellarNodeMessage>(1024);

        let conn = Connector::new(local_node, cfg, actions_sender.clone(), message_writer);

        // start the receiving_service
        tokio::spawn(receiving_service(rd, actions_sender.clone()));

        // run the conn communication
        tokio::spawn(connection_handler(conn, actions_receiver, wr));

        // start the handshake
        actions_sender.send(ConnectorActions::SendHello).await?;

        Ok(UserControls::new(actions_sender, message_receiver))
    }
}

#[cfg(test)]
mod test {
    use crate::connection::errors::Error;
    use crate::{node::NodeInfo, ConnConfig, ConnectorActions, StellarNodeMessage, UserControls};
    use substrate_stellar_sdk::{network::TEST_NETWORK, types::StellarMessage, SecretKey};
    use tokio::sync::mpsc;

    #[test]
    fn create_stellar_overlay_connection_works() {
        let (node_info, cfg) = create_node_and_conn();

        let (actions_sender, _) = mpsc::channel::<ConnectorActions>(1024);
        let (_, relay_message_receiver) = mpsc::channel::<StellarNodeMessage>(1024);

        UserControls::new(actions_sender.clone(), relay_message_receiver);
    }

    #[tokio::test]
    async fn stellar_overlay_connection_send_works() {
        //arrange
        let (node_info, cfg) = create_node_and_conn();

        let (actions_sender, mut actions_receiver) = mpsc::channel::<ConnectorActions>(1024);
        let (_, relay_message_receiver) = mpsc::channel::<StellarNodeMessage>(1024);

        let overlay_connection = UserControls::new(actions_sender.clone(), relay_message_receiver);
        let message_s = StellarMessage::GetPeers;

        //act
        overlay_connection
            .send(message_s.clone())
            .await
            .expect("Should sent message");

        //assert
        let message = actions_receiver.recv().await.unwrap();
        if let ConnectorActions::SendMessage(message) = message {
            assert_eq!(message, message_s);
        } else {
            panic!("Incorrect stellar message")
        }
    }

    #[tokio::test]
    async fn stellar_overlay_connection_listen_works() {
        //arrange
        let (node_info, cfg) = create_node_and_conn();

        let (actions_sender, mut actions_receiver) = mpsc::channel::<ConnectorActions>(1024);
        let (relay_message_sender, relay_message_receiver) =
            mpsc::channel::<StellarNodeMessage>(1024);

        let mut overlay_connection =
            UserControls::new(actions_sender.clone(), relay_message_receiver);
        let error_message = "error message".to_owned();
        relay_message_sender
            .send(StellarNodeMessage::Error(error_message.clone()))
            .await
            .expect("Stellar Relay message should be sent");

        //act
        let message = overlay_connection
            .recv()
            .await
            .expect("Should receive some message");

        //assert
        if let StellarNodeMessage::Error(m) = message {
            assert_eq!(m, error_message);
        } else {
            panic!("Incorrect stellar relay message type")
        }
    }

    #[tokio::test]
    async fn connect_should_fail_incorrect_address() {
        let secret =
            SecretKey::from_encoding("SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73")
                .unwrap();
        let node_info = NodeInfo::new(19, 21, 19, "v19.1.0".to_string(), &TEST_NETWORK);
        let cfg = ConnConfig::new("incorrect address", 11625, secret, 0, false, true, false);

        let stellar_overlay_connection = UserControls::connect(node_info, cfg).await;

        assert!(stellar_overlay_connection.is_err());
        match stellar_overlay_connection.err().unwrap() {
            Error::ConnectionFailed(_) => {}
            _ => {
                panic!("Incorrect error")
            }
        }
    }

    #[tokio::test]
    async fn stellar_overlay_connect_works() {
        let (node_info, cfg) = create_node_and_conn();
        let stellar_overlay_connection = UserControls::connect(node_info, cfg).await;

        assert!(stellar_overlay_connection.is_ok());
    }

    fn create_node_and_conn() -> (NodeInfo, ConnConfig) {
        let secret =
            SecretKey::from_encoding("SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73")
                .unwrap();
        let node_info = NodeInfo::new(19, 21, 19, "v19.1.0".to_string(), &TEST_NETWORK);
        let cfg = ConnConfig::new("34.235.168.98", 11625, secret, 0, false, true, false);
        (node_info, cfg)
    }
}
