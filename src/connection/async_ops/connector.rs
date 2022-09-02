use crate::async_ops::config::{cfg_communication, CfgActions, ConnectionConfig, InnerMessage};
use crate::async_ops::Xdr;
use crate::connection::Error;
use crate::{get_message_length, xdr_converter, HandshakeState};
use std::io::Read;
use std::pin::Pin;
use std::task::{Context, Poll};
use substrate_stellar_sdk::types::StellarMessage;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::{tcp, TcpStream};
use tokio::sync::{broadcast, mpsc};

pub async fn create_stream(
    address: &str,
) -> Result<(tcp::OwnedReadHalf, tcp::OwnedWriteHalf), Error> {
    let mut stream = TcpStream::connect(address)
        .await
        .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

    Ok(stream.into_split())
}

/// This service is for SENDING a stellar message to the server.
/// # Arguments
/// * `w_stream` - the write stream for writing the xdr stellar message
/// * `rx_stream_writer` - the receiver where we get the stellar message from the user.
async fn sending_service(
    mut w_stream: tcp::OwnedWriteHalf,
    mut rx_stream_writer: mpsc::Receiver<Xdr>,
) -> Result<(), Error> {
    loop {
        if let Some(msg) = rx_stream_writer.recv().await {
            w_stream
                .write_all(&msg)
                .await
                .map_err(|e| Error::WriteFailed(e.to_string()))?;
        }
    }
}

/// This service is for RECEIVING a stellar message from the server.
/// # Arguments
/// * `r_stream` - the read stream for reading the xdr stellar message
/// * `tx_stream_reader` - the sender for handling the xdr stellar message
async fn receiving_service(
    mut r_stream: tcp::OwnedReadHalf,
    tx_stream_reader: mpsc::Sender<CfgActions>,
) -> Result<(), Error> {
    loop {
        // let's check for messages.
        let mut sizebuf = [0; 4];
        let message_length_ident = r_stream
            .read(&mut sizebuf)
            .await
            .map_err(|e| Error::Undefined(e.to_string()))?;

        if message_length_ident == 0 {
            // there's no message to be read.
            continue;
        }

        // the actual size of the stellar message
        let message_length = {
            let len = get_message_length(&sizebuf);
            usize::try_from(len).unwrap()
        };

        if message_length_ident == 0 {
            // no message to be read?
            continue;
        }

        // println!("length of message to read: {}", message_length);

        // let's start reading the actual stellar message.
        let mut readbuf: Vec<u8> = vec![0; message_length];

        let read_size = r_stream
            .read(&mut readbuf)
            .await
            .map_err(|e| Error::Undefined(e.to_string()))?;

        // huh. no messages?
        if read_size == 0 {
            continue;
        }

        // first of, let us filter down the message. Not all messages are to be sent to the user.
        // we only care about messages specific for the connector. Disregard others.
        tx_stream_reader
            .send(CfgActions::HandleMessage(readbuf))
            .await?;
    }
}


pub struct UserControls {
    handshake_state: HandshakeState,
    /// This is when we want to send stellar messages
    tx: mpsc::Sender<CfgActions>,
    /// For receiving stellar messages
    rx: mpsc::Receiver<InnerMessage>,
}

impl UserControls {
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_state == HandshakeState::Completed
    }

    pub async fn send(&self, message: StellarMessage) -> Result<(), Error> {
        self.tx
            .send(CfgActions::SendMessage(message))
            .await
            .map_err(Error::from)
    }

    /// Receives Stellar messages from the connection.
    /// # Arguments
    /// * `f` - is an function for handling Stellar messages coming from the Stellar Node.
    pub async fn recv(&mut self, f: fn(StellarMessage)) -> Result<(), Error> {
        if let Some(inner_message) = self.rx.recv().await {
            match inner_message {
                InnerMessage::HandshakeCompleted => {
                    self.handshake_state = HandshakeState::Completed;
                }
                InnerMessage::MessageFromServer(message) => {
                    if self.is_handshake_complete() {
                        f(message);
                    }
                }
                InnerMessage::Problem(_) => {}
            }
        }

        Ok(())
    }
}


/// The actual connection to the Stellar Node.
/// Returns the UserControls for the user to send and receive Stellar messages.
pub async fn connect(mut cfg: ConnectionConfig, addr: &str) -> Result<UserControls, Error> {
    // split the stream for easy handling of read and write
    let (mut rd, mut wr) = create_stream(addr).await?;
    println!("stream created");

    // ------------------ prepare the channels

    // this is a channel to communicate with the streams
    let (xdr_forwarder, xdr_handler) = mpsc::channel::<Xdr>(1024);
    // this is a channel to communicate with the connection/config (this needs renaming)
    let (actions_sender, actions_receiver) = mpsc::channel::<CfgActions>(1024);
    // this is a chanel to communicate with the user/caller.
    let (message_writer, message_receiver) = mpsc::channel::<InnerMessage>(1024);

    // set the channel into the config.
    cfg.set_stream_writer(xdr_forwarder);
    cfg.set_message_writer(message_writer);

    // run the sending service
    tokio::spawn(sending_service(wr, xdr_handler));

    // run the cfg communication
    tokio::spawn(cfg_communication(cfg, actions_receiver));

    // start the handshake
    actions_sender.send(CfgActions::SendHello).await?;

    // start the receiving_service
    tokio::spawn(receiving_service(rd, actions_sender.clone()));

    Ok(UserControls {
        handshake_state: HandshakeState::Connecting,
        tx: actions_sender,
        rx: message_receiver,
    })
}
