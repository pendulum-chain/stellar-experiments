use crate::connection::connector::ConnectorActions;
use crate::{ConnConfig, connection_handler, ConnectionError, Connector, create_stream, receiving_service};
use crate::StellarNodeMessage;
use substrate_stellar_sdk::types::StellarMessage;
use tokio::sync::mpsc;
use crate::node::NodeInfo;

pub struct UserControls {
    /// This is when we want to send stellar messages
    tx: mpsc::Sender<ConnectorActions>,
    /// For receiving stellar messages
    rx: mpsc::Receiver<StellarNodeMessage>,
}

impl UserControls {
    pub(crate) fn new(tx: mpsc::Sender<ConnectorActions>, rx: mpsc::Receiver<StellarNodeMessage>) -> Self {
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
