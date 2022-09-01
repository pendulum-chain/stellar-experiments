use substrate_stellar_sdk::types::StellarMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use crate::connection::Error;
use crate::{get_message_length, parse_authenticated_message};
use crate::async_ops::config::ConnectionConfig;

pub struct Connector{
    tx_stream_writer:mpsc::Sender<Vec<u8>>,
    rx_stream_reader:mpsc::Receiver<Vec<u8>>,
    cfg:ConnectionConfig
}

impl Connector {
    /// Returns channels needed to communicate with the stellar node.
    pub fn new(cfg:ConnectionConfig) -> (Self, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>, mpsc::Sender<Vec<u8>>)  {
        let (tx0,mut rx0) = mpsc::channel::<Vec<u8>>(1024);
        let (tx1,mut rx1) = mpsc::channel::<Vec<u8>>(1024);

        (
            Self {
                tx_stream_writer: tx0.clone(),
                rx_stream_reader: rx1,
                cfg
            },
            tx0,
            rx0,
            tx1,
        )
    }

    pub async fn send_hello_message(&mut self) -> Result<(),Error> {
        let msg = self.cfg.create_hello_message()?;
        self.send_xdr_message(msg).await
    }

    async fn send_xdr_message(&self, message:Vec<u8>) -> Result<(),Error> {
        self.tx_stream_writer.send(message).await
            .map_err(|e| Error::WriteFailed(e.to_string()))
    }

    pub async fn handle_response(&mut self, tx_user:mpsc::Sender<StellarMessage>) -> Result<(),Error> {
        loop {
            if let Some(msg) = self.rx_stream_reader.recv().await {
                match self.cfg.filter_reply(&msg)? {
                    None => { println!("check for send more"); }
                    Some(msg) => {
                        match msg {
                            StellarMessage::Hello(_) => {
                                let msg = self.cfg.create_auth_message()?;
                                self.send_xdr_message(msg).await?;
                            }
                            _ => {
                                println!("sending message::");
                                tx_user.send(msg).await.map_err(|e| Error::SentFailed(e.to_string()))?;
                            }
                        }
                    }
                }
            }
        }
    }
}


pub async fn create_streams(address: &str) -> Result<(OwnedReadHalf, OwnedWriteHalf), Error> {
    let mut stream  = TcpStream::connect(address).await.map_err(|e| {
        Error::ConnectionFailed(e.to_string())
    })?;

    Ok(stream.into_split())
}


/// This service is for SENDING a stellar message to the server.
/// # Arguments
/// * `w_stream` - the write stream for writing the xdr stellar message
/// * `rx_stream_writer` - the receiver where we get the stellar message from the user.
pub async fn sending_service(mut w_stream: OwnedWriteHalf, mut rx_stream_writer:mpsc::Receiver<Vec<u8>>) -> Result<(),Error> {
    loop {
        if let Some(msg) = rx_stream_writer.recv().await {
            w_stream.write_all(&msg).await.map_err(|e| Error::WriteFailed(e.to_string()))?;
        }
    }
}

/// This service is for RECEIVING a stellar message from the server
/// # Arguments
/// * `r_stream` - the read stream for reading the xdr stellar message
/// * `tx_stream_reader` - the sender for handling the xdr stellar message
pub async fn receiving_service(mut r_stream: OwnedReadHalf, tx_stream_reader:mpsc::Sender<Vec<u8>>) -> Result<(),Error> {
    loop {
        let mut readbuf = [0;1024];

        let r_size = r_stream.read(&mut readbuf).await
            .map_err(|e| Error::Undefined(e.to_string()))?;

        if r_size > 0 {
            let message_len = get_message_length(&readbuf);
            let message_len = usize::try_from(message_len).unwrap();

            let data = readbuf[4..(message_len +4)].to_vec();

            // first of, let us filter down the message. Not all messages are to be sent to the user.
            tx_stream_reader.send(data).await.map_err(|e| Error::ReadFailed(e.to_string()))?;
        }
    }
}


/// Connects to the stellar node and starts the handshake
/// # Arguments
/// * `cfg` - the configuration of our connection
/// * `addr` - address of the Stellar node we want to connect to. Should already include the port #
/// * `tx_user` - the sender for sending stellar messages to the user
pub async fn initialize(cfg:ConnectionConfig, addr:&str, tx_user:mpsc::Sender<StellarMessage>) -> Result<mpsc::Sender<Vec<u8>>,Error> {
    // prepare all the channels
    let (mut conn, tx_stream_writer, rx_stream_writer, tx) = Connector::new(cfg);

    // split the stream for easy handling of read and write
    let (mut rd, mut wr) = create_streams(addr).await?;

    // run the sending service
    tokio::spawn(sending_service(wr,rx_stream_writer));

    // start the handshake
    conn.send_hello_message().await?;

    // for handling the response, before sending it to the user
    tokio::spawn(async move {
        conn.handle_response(tx_user).await?;
        Ok::<_, Error>(())
    });

    // start the receiving service
    tokio::spawn(async move {
    receiving_service(rd,tx).await?;
        Ok::<_, Error>(())
    });

    Ok(tx_stream_writer)
}
