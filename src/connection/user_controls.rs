use core::time::Duration;
use crate::connection::errors::Error;
use crate::connection::connector::ConnectorActions;
use crate::node::NodeInfo;
use crate::StellarNodeMessage;
use crate::{
    connection_handler, create_stream, receiving_service, ConnConfig, ConnectionError, Connector,
};
use substrate_stellar_sdk::types::StellarMessage;
use tokio::sync::mpsc;

// pub struct UserControls {
//     /// This is when we want to send stellar messages
//     tx: mpsc::Sender<ConnectorActions>,
//     /// For receiving stellar messages
//     rx: mpsc::Receiver<StellarNodeMessage>,
// }

pub struct UserControls {
	/// This is when we want to send stellar messages
	tx: mpsc::Sender<ConnectorActions>,
	/// For receiving stellar messages
	rx: mpsc::Receiver<StellarNodeMessage>,
	local_node: NodeInfo,
	cfg: ConnConfig,
	/// Maximum retries for reconnection
	max_retries: u8,
}

impl UserControls {
	fn new(
		tx: mpsc::Sender<ConnectorActions>,
		rx: mpsc::Receiver<StellarNodeMessage>,
		max_retries: u8,
		local_node: NodeInfo,
		cfg: ConnConfig,
	) -> Self {
		UserControls {
			tx,
			rx,
			local_node,
			cfg,
			max_retries,
		}
	}

	pub async fn send(&self, message: StellarMessage) -> Result<(), Error> {
		self.tx
			.send(ConnectorActions::SendMessage(message))
			.await
			.map_err(Error::from)
	}

	/// Receives Stellar messages from the connection.
	/// Restarts the connection when lost.
	pub async fn listen(&mut self) -> Option<StellarNodeMessage> {
		let res = self.rx.recv().await;

		// Reconnection only when the maximum number of retries has not been reached.
		if let Some(StellarNodeMessage::Timeout) = &res {
			let mut retries = 0;
			while retries < self.max_retries {
				log::info!("Connection timed out. Reconnecting to {:?}...", &self.cfg.address);
				if let Ok(new_user) =
					UserControls::connect(self.local_node.clone(), self.cfg.clone())
						.await
				{
					self.max_retries = new_user.max_retries;
					self.tx = new_user.tx;
					self.rx = new_user.rx;
					log::info!("Reconnected to {:?}!", &self.cfg.address);
					return self.rx.recv().await
				} else {
					retries += 1;
					log::error!(
						"Failed to reconnect! # of retries left: {}. Retrying in 3 seconds...",
						self.max_retries
					);
					tokio::time::sleep(Duration::from_secs(3)).await;
				}
			}
		}
		res
	}

	/// Triggers connection to the Stellar Node.
	/// Returns the UserControls for the user to send and receive Stellar messages.
	pub async fn connect(
		local_node: NodeInfo,
		cfg: ConnConfig,
	) -> Result<UserControls, Error> {
		let retries = cfg.retries;
		let timeout_in_secs = cfg.timeout_in_secs;
		// split the stream for easy handling of read and write
		let (rd, wr) = create_stream(&cfg.address()).await?;
		// ------------------ prepare the channels
		// this is a channel to communicate with the connection/config (this needs renaming)
		let (tx, actions_receiver) = mpsc::channel::<ConnectorActions>(1024);
		// this is a channel to communicate with the user/caller.
		let (relay_message_sender, rx) =
			mpsc::channel::<StellarNodeMessage>(1024);
		let overlay_connection = UserControls::new(
			tx.clone(),
			rx,
			cfg.retries,
			local_node,
			cfg,
		);
		let connector = Connector::new(
			overlay_connection.local_node.clone(),
			overlay_connection.cfg.clone(),
			tx.clone(),
			relay_message_sender,
		);
		// start the receiving_service
		tokio::spawn(receiving_service(rd, tx.clone()));
		// run the connector communication
		tokio::spawn(connection_handler(connector, actions_receiver, wr));
		// start the handshake
		tx.send(ConnectorActions::SendHello).await?;
		Ok(overlay_connection)
	}
}

#[cfg(test)]
mod test {
	use crate::{
		node::NodeInfo, ConnConfig, ConnectorActions, UserControls,
		StellarNodeMessage,
	};
	use substrate_stellar_sdk::{network::TEST_NETWORK, types::StellarMessage, SecretKey};
	use tokio::sync::mpsc;

	#[test]
	fn create_stellar_overlay_connection_works() {
		let (node_info, cfg) = create_node_and_conn();

		let (tx, _) = mpsc::channel::<ConnectorActions>(1024);
		let (_, rx) = mpsc::channel::<StellarNodeMessage>(1024);

		UserControls::new(
			tx.clone(),
			rx,
			cfg.retries,
			node_info,
			cfg,
		);
	}

	#[tokio::test]
	async fn stellar_overlay_connection_send_works() {
		//arrange
		let (node_info, cfg) = create_node_and_conn();

		let (tx, mut actions_receiver) = mpsc::channel::<ConnectorActions>(1024);
		let (_, rx) = mpsc::channel::<StellarNodeMessage>(1024);

		let overlay_connection = UserControls::new(
			tx.clone(),
			rx,
			cfg.retries,
			node_info,
			cfg,
		);
		let message_s = StellarMessage::GetPeers;

		//act
		overlay_connection.send(message_s.clone()).await.expect("Should sent message");

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

		let (tx, mut actions_receiver) = mpsc::channel::<ConnectorActions>(1024);
		let (relay_message_sender, rx) =
			mpsc::channel::<StellarNodeMessage>(1024);

		let mut overlay_connection = UserControls::new(
			tx.clone(),
			rx,
			cfg.retries,
			node_info,
			cfg,
		);
		let error_message = "error message".to_owned();
		relay_message_sender
			.send(StellarNodeMessage::Error(error_message.clone()))
			.await
			.expect("Stellar Relay message should be sent");

		//act
		let message = overlay_connection.listen().await.expect("Should receive some message");

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
        use crate::connection::ConnectionError;
		assert!(stellar_overlay_connection.is_err());
		match stellar_overlay_connection.err().unwrap() {
			ConnectionError::ConnectionFailed(_) => {},
			_ => {
				panic!("Incorrect error")
			},
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
