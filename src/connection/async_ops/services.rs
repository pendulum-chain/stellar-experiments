use crate::async_ops::connector::{ConnectorActions, Connector, ConnectionState};
use crate::async_ops::Xdr;
use crate::connection::Error;
use crate::{get_message_length, xdr_converter, HandshakeState, ReadState};
use std::io::Read;
use std::pin::Pin;
use std::task::{Context, Poll};
use substrate_stellar_sdk::types::StellarMessage;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::{tcp, TcpStream};
use tokio::sync::mpsc;



pub enum StreamActions {
    ChangeReading(bool, ReadState),
    StartWriting(Xdr),
}

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
        if let Some((_,msg)) = rx_stream_writer.recv().await {
            w_stream
                .write_all(&msg)
                .await
                .map_err(|e| Error::WriteFailed(e.to_string()))?;
        }
    }
}



/// checks the message length.
async fn check_message_length(message_id:u32, r_stream:&mut tcp::OwnedReadHalf) -> Option<usize> {
    // let's check for messages.
    let mut sizebuf = [0; 4];

    let _ = r_stream
        .try_read(&mut sizebuf).unwrap_or(0);


    println!("\npid: {:?} next message length sizebuf: {:?}", message_id, sizebuf);

    if sizebuf.len() > 0 {
        let len = get_message_length(&sizebuf);
        println!("  pid: {:?} ----> the length: {:?}", message_id, len);

        if len > 0 {
           return usize::try_from(len).ok();
        }
    }

    None
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
                    cfg.process_raw_message(xdr).await?;
                }
                ConnectorActions::SendHello => {
                    cfg.send_hello_message().await?;
                }
            }
        }
    }
}

/// This service is for RECEIVING a stellar message from the server.
/// # Arguments
/// * `r_stream` - the read stream for reading the xdr stellar message
/// * `tx_stream_reader` - the sender for handling the xdr stellar message
async fn receiving_service(
    mut r_stream: tcp::OwnedReadHalf,
    tx_stream_reader: mpsc::Sender<ConnectorActions>,
) -> Result<(), Error> {
    let mut message_id = 0;

    loop {
        match r_stream.readable().await {
            Ok(_) => {
                // let's check for the size of the message. If it's not enough, skip it.
                if let Some(message_length) = check_message_length(message_id, &mut r_stream).await {

                    // let's start reading the actual stellar message.
                    let mut readbuf: Vec<u8> = vec![0; message_length];

                    let read_len = r_stream
                        .try_read(&mut readbuf)
                        .map_err(|e| Error::ReadFailed(e.to_string()))?;



                    // if message_length < 10000 {
                    //     println!("  ---> pid: {:?} readbuf: {:?}", message_id, readbuf);
                    // }

                    // only when the message has the exact expected size bytes, should we send to user.
                    if read_len == message_length {
                        println!("  ----> pid: {:?} sending to connection", message_id);
                        tx_stream_reader
                            .send(ConnectorActions::HandleMessage((message_id,readbuf)))
                            .await?;
                    }
                }
            }
            Err(e) => {
                println!("pid: {:?} NOT YET READABLE: {:?}",message_id, e);
            }
        }
        message_id+=1;
    }

}


pub struct UserControls {
    /// This is when we want to send stellar messages
    tx: mpsc::Sender<ConnectorActions>,
    /// For receiving stellar messages
    rx: mpsc::Receiver<ConnectionState>,
}

impl UserControls {

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


/// The actual connection to the Stellar Node.
/// Returns the UserControls for the user to send and receive Stellar messages.
pub async fn connect(mut conn: Connector, addr: &str) -> Result<UserControls, Error> {
    // split the stream for easy handling of read and write
    let (mut rd, mut wr) = create_stream(addr).await?;
    println!("stream created");

    // ------------------ prepare the channels

    // this is a channel between the connector and the streams
    let (xdr_forwarder, xdr_handler) = mpsc::channel::<Xdr>(1024);

    // this is a channel to communicate with the connection/config (this needs renaming)
    let (actions_sender, actions_receiver) = mpsc::channel::<ConnectorActions>(1024);
    // this is a chanel to communicate with the user/caller.
    let (message_writer, message_receiver) = mpsc::channel::<ConnectionState>(1024);

    // set the channel into the config.
    conn.set_stream_writer(xdr_forwarder);
    conn.set_message_writer(message_writer);

    // run the sending service
    tokio::spawn(sending_service(wr, xdr_handler));


    // start the receiving_service
    tokio::spawn(receiving_service(rd, actions_sender.clone()));

    // run the conn communication
    tokio::spawn(comm_service(conn, actions_receiver));

    // start the handshake
    actions_sender.send(ConnectorActions::SendHello).await?;


    Ok(UserControls {
        tx: actions_sender,
        rx: message_receiver,
    })
}


