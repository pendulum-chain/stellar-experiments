use std::future::Future;
use crate::async_ops::connector::{ConnectorActions, Connector, ConnectionState};
use crate::async_ops::Xdr;
use crate::connection::Error;
use crate::{get_xdr_message_length, xdr_converter, HandshakeState, ReadState};
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

/// checks the length of the next stellar message.
async fn next_message_length(r_stream:&mut tcp::OwnedReadHalf) -> usize {
    // let's check for messages.
    let mut sizebuf = [0; 4];

    let buff_len = r_stream.read(&mut sizebuf).await.unwrap_or(0);
    if buff_len == 0 {
        return 0;
    }

    get_xdr_message_length(&sizebuf)
}



async fn write_to_stream(message_id:u32, readbuf:Vec<u8>, tx_stream_reader: &mpsc::Sender<ConnectorActions> )
    -> Result<(), Error> {

    Ok(())
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

    // holds the number of bytes that were missing from the previous stellar message.
    let mut lack_bytes_from_prev = 0;
    let mut readbuf: Vec<u8> = vec![];

    loop {
        // check whether or not we should read the bytes as:
        // 1. the length of the next stellar message
        // 2. the remaining bytes of the previous stellar message
        match r_stream.readable().await {
            Ok(_) if lack_bytes_from_prev == 0 => {
                // if there are no more bytes lacking from the previous message,
                // then check the size of next stellar message.
                // If it's not enough, skip it.
                let xpect_msg_len = next_message_length(&mut r_stream).await;
                // println!("\npid: {:?} next message length: {:?}", message_id, xpect_msg_len);

                if xpect_msg_len > 0 {
                    // let's start reading the actual stellar message.
                    readbuf = vec![0;xpect_msg_len];

                    let actual_msg_len = r_stream
                        .read(&mut readbuf).await
                        .map_err(|e| Error::ReadFailed(e.to_string()))?;

                     //println!("  ---> pid: {:?} xpected_msg_len: {} actual_msg_len: {}", message_id, xpect_msg_len,actual_msg_len);

                    // only when the message has the exact expected size bytes, should we send to user.
                    if actual_msg_len == xpect_msg_len {
                        tx_stream_reader
                            .send(ConnectorActions::HandleMessage((message_id,readbuf.clone())))
                            .await?;

                        readbuf.clear();
                        message_id +=1;

                    } else {
                        // so the next bytes are remnants from the previous stellar message.
                        // save it and read it on the next loop.
                        lack_bytes_from_prev = xpect_msg_len - actual_msg_len;
                        readbuf = readbuf[0..actual_msg_len].to_owned();
                        // println!("\n  ---> pid: {:?} not enough readbuf: {:?}", message_id, readbuf);

                    }
                }
            }
            Ok(_) => {
                // let's read the continuation number of bytes from the previous message.
                let mut cont_buf = vec![0;lack_bytes_from_prev];

                let actual_msg_len = r_stream
                    .read(&mut cont_buf).await
                    .map_err(|e| Error::ReadFailed(e.to_string()))?;

                //println!("  ---> pid: {:?} contbuf: xpected_msg_len: {} actual_msg_len: {}", message_id, lack_bytes_from_prev,actual_msg_len);

                if actual_msg_len == lack_bytes_from_prev {
                    readbuf.append(&mut cont_buf);

                    tx_stream_reader
                        .send(ConnectorActions::HandleMessage((message_id,readbuf.clone())))
                        .await?;

                    lack_bytes_from_prev = 0;
                    readbuf.clear();
                    message_id +=1;

                } else if actual_msg_len > 0 {
                    lack_bytes_from_prev -= actual_msg_len;
                    cont_buf = cont_buf[0..actual_msg_len].to_owned();
                    //cont_buf.truncate(lack_bytes_from_prev);
                    readbuf.append(&mut cont_buf);
                }

            }
            Err(e) => {
                println!("STREAM NOT YET READABLE: {:?}", e);
            }
        }

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
                    cfg.process_raw_message(xdr).await?;
                }
                ConnectorActions::SendHello => {
                    cfg.send_hello_message().await?;
                }
                ConnectorActions::IncreaseRemoteSequence => {
                    cfg.increment_remote_sequence();
                    //cfg.check_to_send_more()

                }
            }
        }
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


