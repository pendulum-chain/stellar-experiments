use crate::async_ops::ConnectorActions;
use crate::errors::Error;
use crate::ConnectionState;
use substrate_stellar_sdk::types::StellarMessage;
use tokio::sync::mpsc;

pub struct UserControls {
    /// This is when we want to send stellar messages
    tx: mpsc::Sender<ConnectorActions>,
    /// For receiving stellar messages
    rx: mpsc::Receiver<ConnectionState>,
}

impl UserControls {
    pub fn new(tx: mpsc::Sender<ConnectorActions>, rx: mpsc::Receiver<ConnectionState>) -> Self {
        UserControls { tx, rx }
    }
    pub async fn send(&self, message: StellarMessage) -> Result<(), Error> {
        self.tx
            .send(ConnectorActions::SendMessage(message))
            .await
            .map_err(Error::from)
    }

    /// Receives Stellar messages from the connection.
    pub async fn recv(&mut self) -> Option<ConnectionState> {
        self.rx.recv().await
    }
}
