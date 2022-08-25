mod connection;
pub mod helper;
pub mod node;
pub mod xdr_converter;

pub use connection::*;
use std::fs::read;

use std::io::prelude::*;
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::node::NodeInfo;
use crate::xdr_converter::{get_message_length, parse_authenticated_message};
use hmac::Hmac;
use stellar::compound_types::LimitedString;
use stellar::types::{
    Auth, AuthCert, AuthenticatedMessage, AuthenticatedMessageV0, Curve25519Public, Error, Hello,
    HmacSha256Mac, SendMore, Signature, StellarMessage, Uint256,
};
use stellar::{Curve25519Secret, PublicKey, XdrCodec};
use substrate_stellar_sdk as stellar;
use substrate_stellar_sdk::network::Network;
use substrate_stellar_sdk::SecretKey;

pub struct Config {
    secret_key: SecretKey,
    secret_key_ecdh: String,
    auth_time: u64,
    connection_local_nonce: String,
    node_info: NodeInfo,
}

fn main() -> std::io::Result<()> {
    let addr = "135.181.16.110:11625";
    // let addr = "135.181.16.110:11625";
    let mut stream = TcpStream::connect(addr)?;

    let secret = stellar::SecretKey::from_encoding(
        "SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73",
    )
    .unwrap();


    let node_info = NodeInfo::new(
        19,
        21,
        19,
        "v19.1.0".to_string(),
        &Network::new(b"Public Global Stellar Network ; September 2015"),
    );

    let mut conn = Connection::new(
        node_info,
        secret,
        0,
        false,
    "135.181.16.110:11625"
    ).expect("SHOULD WORK!");

    conn.start().expect("hoooy should be ok!!");

    let msg =  StellarMessage::GetScpState(20);
    conn.send_stellar_message(msg).expect("SHOULD SEND THE GETSCPSTATE!!!");
    conn.read_response().expect("OH COME ON, RESPONSE!!!");

    Ok(())

    // let hello_msg = conn.create_hello_message();
    // let auth_hello_msg = conn.authenticate_message(hello_msg);
    // let xdr_auth_hello_msg = xdr_converter::from_authenticated_message(&auth_hello_msg).unwrap();
    // stream.write(&xdr_auth_hello_msg)?;

    //request a message
    // let sendmore = SendMore{num_messages: 10 };
    // let authenticated_message = AuthenticatedMessage::V0(AuthenticatedMessageV0 {
    //     sequence: 0,
    //     message: StellarMessage::SendMore(sendmore.clone()),
    //     mac: HmacSha256Mac{
    //         mac: [0;32],
    //     }
    // });
    // let buf = XdrCodec::to_xdr(&authenticated_message);
    // stream.write(&buf)?;

    //read loop
    // let mut readbuf = [0; 1024];
    // loop {
    //     let size = stream.read(&mut readbuf)?;
    //
    //     if size > 0 {
    //         let msg_len = get_message_length(&readbuf);
    //         let msg_len = usize::try_from(msg_len).unwrap();
    //
    //         if msg_len <= readbuf.len() {
    //             let data = &readbuf[4..msg_len + 4];
    //
    //             let res = parse_authenticated_message(data).expect("should return okay");
    //             println!("stream result: {:?}", res);
    //             let res = conn.handle_message(res.message);
    //             println!("handle message result: {:?}", res);
    //         }
    //     }
    // }
}
