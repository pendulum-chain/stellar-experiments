use crate::connection::connector::{Connector, ConnectorActions};
use crate::connection::helper::time_now;
use crate::connection::xdr_converter::get_xdr_message_length;
use crate::node::NodeInfo;
use crate::ConnectionError;
use crate::{ConnConfig, StellarNodeMessage, UserControls};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{tcp, TcpStream};
use tokio::sync::mpsc;
use tokio::time::error::Elapsed;
use tokio::time::Timeout;

pub(crate) async fn create_stream(
    address: &str,
) -> Result<(tcp::OwnedReadHalf, tcp::OwnedWriteHalf), ConnectionError> {
    let stream = TcpStream::connect(address)
        .await
        .map_err(|e| ConnectionError::ConnectionFailed(e.to_string()))?;

    Ok(stream.into_split())
}

/// checks the length of the next stellar message.
async fn next_message_length(r_stream: &mut tcp::OwnedReadHalf) -> usize {
    // let's check for messages.
    let mut sizebuf = [0; 4];

    if r_stream.read(&mut sizebuf).await.unwrap_or(0) == 0 {
        return 0;
    }

    get_xdr_message_length(&sizebuf)
}

/// reads data from the stream and store to buffer
async fn read_stream(
    r_stream: &mut tcp::OwnedReadHalf,
    buffer: &mut [u8],
) -> Result<usize, ConnectionError> {
    r_stream
        .read(buffer)
        .await
        .map_err(|e| ConnectionError::ReadFailed(e.to_string()))
}

/// sends the HandleMessage action to the connector
async fn handle_message(
    tx_stream_reader: &mpsc::Sender<ConnectorActions>,
    proc_id: u32,
    xdr_msg: Vec<u8>,
) -> Result<(), ConnectionError> {
    tx_stream_reader
        .send(ConnectorActions::HandleMessage((proc_id, xdr_msg)))
        .await
        .map_err(ConnectionError::from)
}

/// reads a continuation of bytes that belong to the previous message
///
/// # Arguments
/// * `r_stream` - the read stream for reading the xdr stellar message
/// * `sender` - the sender for actions a Connector must do
/// * `lack_bytes_from_prev` - the number of bytes remaining, to complete the previous message
/// * `proc_id` - the process id, used for tracing.
/// * `readbuf` - the buffer that holds the bytes of the previous and incomplete message
async fn read_unfinished_message(
    r_stream: &mut tcp::OwnedReadHalf,
    sender: &mpsc::Sender<ConnectorActions>,
    lack_bytes_from_prev: &mut usize,
    proc_id: &mut u32,
    readbuf: &mut Vec<u8>,
) -> Result<(), ConnectionError> {
    // let's read the continuation number of bytes from the previous message.
    let mut cont_buf = vec![0; *lack_bytes_from_prev];

    let actual_msg_len = read_stream(r_stream, &mut cont_buf).await?;

    // this partial message completes the previous message.
    if actual_msg_len == *lack_bytes_from_prev {
        log::trace!(
            "proc_id: {} received continuation from the previous message.",
            proc_id
        );
        readbuf.append(&mut cont_buf);

        handle_message(sender, *proc_id, readbuf.clone()).await?;

        *lack_bytes_from_prev = 0;
        readbuf.clear();
        *proc_id += 1;

        return Ok(());
    }

    // this partial message is not enough to complete the previous message.
    if actual_msg_len > 0 {
        *lack_bytes_from_prev -= actual_msg_len;
        cont_buf = cont_buf[0..actual_msg_len].to_owned();
        readbuf.append(&mut cont_buf);
        log::trace!("proc_id: {} not enough bytes to complete the previous message. Need {} bytes to complete."
                        ,proc_id, lack_bytes_from_prev);
    }

    Ok(())
}

/// reads a number of bytes based on the expected message length.
///
/// # Arguments
/// * `r_stream` - the read stream for reading the xdr stellar message
/// * `sender` - the sender for actions a Connector must do
/// * `lack_bytes_from_prev` - the number of bytes remaining, to complete the previous message
/// * `proc_id` - the process id, used for tracing.
/// * `readbuf` - the buffer that holds the bytes of the previous and incomplete message
/// * `xpect_msg_len` - the expected # of bytes of the Stellar message
async fn read_message(
    r_stream: &mut tcp::OwnedReadHalf,
    sender: &mpsc::Sender<ConnectorActions>,
    lack_bytes_from_prev: &mut usize,
    proc_id: &mut u32,
    readbuf: &mut Vec<u8>,
    xpect_msg_len: usize,
) -> Result<(), ConnectionError> {
    let actual_msg_len = read_stream(r_stream, readbuf).await?;

    // only when the message has the exact expected size bytes, should we send to user.
    if actual_msg_len == xpect_msg_len {
        handle_message(sender, *proc_id, readbuf.clone()).await?;
        readbuf.clear();
        *proc_id += 1;
        return Ok(());
    }

    // The next bytes are remnants from the previous stellar message.
    // save it and read it on the next loop.
    *lack_bytes_from_prev = xpect_msg_len - actual_msg_len;
    *readbuf = readbuf[0..actual_msg_len].to_owned();
    log::trace!(
        "proc_id: {} received only partial message. Need {} bytes to complete.",
        proc_id,
        lack_bytes_from_prev
    );

    Ok(())
}

/// This service is for RECEIVING a stellar message from the server.
/// # Arguments
/// * `r_stream` - the read stream for reading the xdr stellar message
/// * `tx_stream_reader` - the sender for handling the xdr stellar message
pub(crate) async fn receiving_service(
    mut r_stream: tcp::OwnedReadHalf,
    tx_stream_reader: mpsc::Sender<ConnectorActions>,
) -> Result<(), ConnectionError> {
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

                if xpect_msg_len == 0 {
                    // there's nothing to read; wait for the next iteration
                    continue;
                }

                // let's start reading the actual stellar message.
                readbuf = vec![0; xpect_msg_len];

                read_message(
                    &mut r_stream,
                    &tx_stream_reader,
                    &mut lack_bytes_from_prev,
                    &mut proc_id,
                    &mut readbuf,
                    xpect_msg_len,
                )
                .await?;
            }
            Ok(_) => {
                // let's read the continuation number of bytes from the previous message.
                read_unfinished_message(
                    &mut r_stream,
                    &tx_stream_reader,
                    &mut lack_bytes_from_prev,
                    &mut proc_id,
                    &mut readbuf,
                )
                .await?;
            }

            Err(e) => {
                log::info!("ERROR ERROR! {:?}", e);
            }
        }
    }
}

async fn _connection_handler(
    actions: ConnectorActions,
    conn: &mut Connector,
    receiver: &mut mpsc::Receiver<ConnectorActions>,
    w_stream: &mut tcp::OwnedWriteHalf,
) -> Result<(), ConnectionError> {
    match actions {
        // start the connection to Stellar node with a 'hello'
        ConnectorActions::SendHello => {
            log::info!("Starting Handshake with Hello.");
            let msg = conn.create_hello_message(time_now())?;
            w_stream
                .write_all(&msg)
                .await
                .map_err(|e| ConnectionError::WriteFailed(e.to_string()))?;
        }

        // write message to the stream
        ConnectorActions::SendMessage(msg) => {
            let xdr_msg = conn.create_xdr_message(msg)?;
            w_stream
                .write_all(&xdr_msg)
                .await
                .map_err(|e| ConnectionError::WriteFailed(e.to_string()))?;
        }

        // handle incoming message from the stream
        ConnectorActions::HandleMessage(xdr) => {
            conn.process_raw_message(xdr).await?;
        }
    }

    Ok(())
}

/// Handles actions for the connection.
/// # Arguments
/// * `conn` - the Connector that would send/handle messages to/from Stellar Node
/// * `receiver` - The receiver for actions that the Connector should do.
/// * `w_stream` -> the write half of the TcpStream to connect to the Stellar Node
pub(crate) async fn connection_handler(
    mut conn: Connector,
    mut receiver: mpsc::Receiver<ConnectorActions>,
    mut w_stream: tcp::OwnedWriteHalf,
) -> Result<(), ConnectionError> {
    let mut retry = 0;
    loop {
        match tokio::time::timeout(Duration::from_secs(conn.timeout_in_secs), receiver.recv()).await
        {
            Ok(Some(action)) => {
                retry = 0;
                _connection_handler(action, &mut conn, &mut receiver, &mut w_stream).await?;
            }
            Ok(None) => {}
            Err(elapsed) => {
                log::error!(
                    "{} for receiving messages. Retry: {}",
                    elapsed.to_string(),
                    retry
                );
                if retry >= conn.retries {
                    conn.send_to_user(StellarNodeMessage::Timeout).await?;
                    return Err(ConnectionError::ConnectionFailed(format!(
                        "TIMED OUT! elapsed time: {:?}",
                        elapsed.to_string()
                    )));
                }
                retry += 1;
            }
        }
    }
}
