mod connection;
pub mod helper;
pub mod node;
pub mod xdr_converter;

pub use connection::*;

use std::io::prelude::*;
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::node::NodeInfo;
use hmac::Hmac;
use stellar::compound_types::LimitedString;
use stellar::types::{
    Auth, AuthCert, AuthenticatedMessage, AuthenticatedMessageV0, Curve25519Public, Error, Hello,
    HmacSha256Mac, SendMore, Signature, StellarMessage, Uint256,
};
use stellar::{Curve25519Secret, PublicKey, XdrCodec};
use substrate_stellar_sdk as stellar;
use substrate_stellar_sdk::network::Network;

fn main() -> std::io::Result<()> {
    let addr = "139.59.221.81:11625";
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
        Network::new(b"Public Global Stellar Network ; September 2015"),
    );

    let mut conn = Connection::new(node_info, secret, 0);

    let hello_msg = conn.create_hello_message();
    let auth_hello_msg = conn.authenticate_message(hello_msg);
    let xdr_auth_hello_msg = xdr_converter::from_authenticated_message(&auth_hello_msg).unwrap();
    stream.write(&xdr_auth_hello_msg)?;
    //stream.write(&message);

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
    let mut readbuf = [0; 128];
    loop {
        let size = stream.read(&mut readbuf)?;

        if size > 0 {
            let res = xdr_converter::to_authenticated_message(&readbuf);
            println!("value of res: {:?}", res);
        }
    }
}
