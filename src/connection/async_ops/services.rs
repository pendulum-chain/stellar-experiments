use crate::async_ops::connector::{ConnectionState, Connector, ConnectorActions};

use crate::async_ops::user_controls::UserControls;
use crate::async_ops::Xdr;
use crate::errors::Error;
use crate::helper::time_now;
use crate::{get_xdr_message_length, ReadState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{tcp, TcpStream};
use tokio::sync::mpsc;

pub enum StreamActions {
    ChangeReading(bool, ReadState),
    StartWriting(Xdr),
}

pub async fn create_stream(
    address: &str,
) -> Result<(tcp::OwnedReadHalf, tcp::OwnedWriteHalf), Error> {
    let stream = TcpStream::connect(address)
        .await
        .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

    Ok(stream.into_split())
}

/// checks the length of the next stellar message.
async fn next_message_length(r_stream: &mut tcp::OwnedReadHalf) -> usize {
    // let's check for messages.
    let mut sizebuf = [0; 4];

    let buff_len = r_stream.read(&mut sizebuf).await.unwrap_or(0);
    if buff_len == 0 {
        return 0;
    }

    get_xdr_message_length(&sizebuf)
}

/// This service is for RECEIVING a stellar message from the server.
/// # Arguments
/// * `r_stream` - the read stream for reading the xdr stellar message
/// * `tx_stream_reader` - the sender for handling the xdr stellar message
async fn receiving_service(
    mut r_stream: tcp::OwnedReadHalf,
    tx_stream_reader: mpsc::Sender<ConnectorActions>,
) -> Result<(), Error> {
    let mut proc_id = 0;

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
                log::trace!(
                    "proc_id: {} The next message length: {}",
                    proc_id,
                    xpect_msg_len
                );

                if xpect_msg_len > 0 {
                    // let's start reading the actual stellar message.
                    readbuf = vec![0; xpect_msg_len];

                    let actual_msg_len = r_stream
                        .read(&mut readbuf)
                        .await
                        .map_err(|e| Error::ReadFailed(e.to_string()))?;

                    // only when the message has the exact expected size bytes, should we send to user.
                    if actual_msg_len == xpect_msg_len {
                        tx_stream_reader
                            .send(ConnectorActions::HandleMessage((proc_id, readbuf.clone())))
                            .await?;

                        readbuf.clear();
                        proc_id += 1;
                    } else {
                        // so the next bytes are remnants from the previous stellar message.
                        // save it and read it on the next loop.
                        lack_bytes_from_prev = xpect_msg_len - actual_msg_len;
                        readbuf = readbuf[0..actual_msg_len].to_owned();
                        log::trace!(
                            "proc_id: {} received only partial message. Need {} bytes to complete.",
                            proc_id,
                            lack_bytes_from_prev
                        );
                    }
                }
            }
            Ok(_) => {
                // let's read the continuation number of bytes from the previous message.
                let mut cont_buf = vec![0; lack_bytes_from_prev];

                let actual_msg_len = r_stream
                    .read(&mut cont_buf)
                    .await
                    .map_err(|e| Error::ReadFailed(e.to_string()))?;

                // this partial message, completes the previous message.
                if actual_msg_len == lack_bytes_from_prev {
                    log::trace!(
                        "proc_id: {} received continuation from the previous message.",
                        proc_id
                    );
                    readbuf.append(&mut cont_buf);

                    tx_stream_reader
                        .send(ConnectorActions::HandleMessage((proc_id, readbuf.clone())))
                        .await?;

                    lack_bytes_from_prev = 0;
                    readbuf.clear();
                    proc_id += 1;
                }
                // this partial message is not enough to complete the previous message.
                else if actual_msg_len > 0 {
                    lack_bytes_from_prev -= actual_msg_len;
                    cont_buf = cont_buf[0..actual_msg_len].to_owned();
                    readbuf.append(&mut cont_buf);
                    log::trace!("proc_id: {} not enough bytes to complete the previous message. Need {} bytes to complete."
                        ,proc_id, lack_bytes_from_prev);
                }
            }
            Err(_) => {}
        }
    }
}

/// Handles actions for the connection.
/// # Arguments
/// * `conn` - the Connector that would send/handle messages to/from Stellar Node
/// * `receiver` - The receiver for actions that the Connector should do.
/// * `w_stream` -> the write half of the TcpStream to connect to the Stellar Node
pub async fn connection_handler(
    mut conn: Connector,
    mut receiver: mpsc::Receiver<ConnectorActions>,
    mut w_stream: tcp::OwnedWriteHalf,
) -> Result<(), Error> {
    loop {
        match receiver.recv().await {
            // write message to the stream
            Some(ConnectorActions::SendMessage(msg)) => {
                let xdr_msg = conn.create_xdr_message(msg)?;
                w_stream
                    .write_all(&xdr_msg)
                    .await
                    .map_err(|e| Error::WriteFailed(e.to_string()))?;
            }

            // handle incoming message from the stream
            Some(ConnectorActions::HandleMessage(xdr)) => {
                conn.process_raw_message(xdr).await?;
            }

            // start the connection to Stellar node with a 'hello'
            Some(ConnectorActions::SendHello) => {
                log::info!("Starting Handshake with Hello.");
                let msg = conn.create_hello_message(time_now())?;
                w_stream
                    .write_all(&msg)
                    .await
                    .map_err(|e| Error::WriteFailed(e.to_string()))?;
            }

            None => {}
        }
    }
}

/// Triggers connection to the Stellar Node.
/// Returns the UserControls for the user to send and receive Stellar messages.
pub async fn connect(mut conn: Connector, addr: &str) -> Result<UserControls, Error> {
    // split the stream for easy handling of read and write
    let (rd, wr) = create_stream(addr).await?;

    // ------------------ prepare the channels

    // this is a channel to communicate with the connection/config (this needs renaming)
    let (actions_sender, actions_receiver) = mpsc::channel::<ConnectorActions>(1024);
    // this is a chanel to communicate with the user/caller.
    let (message_writer, message_receiver) = mpsc::channel::<ConnectionState>(1024);

    // set the channel into the config.
    // conn.set_stream_writer(xdr_forwarder);
    conn.set_sender_to_self(actions_sender.clone());
    conn.set_message_writer(message_writer);

    // start the receiving_service
    tokio::spawn(receiving_service(rd, actions_sender.clone()));

    // run the conn communication
    tokio::spawn(connection_handler(conn, actions_receiver, wr));

    // start the handshake
    actions_sender.send(ConnectorActions::SendHello).await?;

    Ok(UserControls::new(actions_sender, message_receiver))
}
