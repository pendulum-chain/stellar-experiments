mod connection;
pub mod node;
pub mod converter;
pub mod helper;


pub use connection::*;

use std::io::prelude::*;
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use stellar::{PublicKey, XdrCodec, Curve25519Secret};
use stellar::compound_types::LimitedString;
use stellar::types::{Curve25519Public, AuthCert, Hello, Auth, Signature, Uint256, StellarMessage, Error, AuthenticatedMessage, AuthenticatedMessageV0, HmacSha256Mac, SendMore};
use substrate_stellar_sdk as stellar;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use substrate_stellar_sdk::network::Network;
use crate::converter::xdr_buffer_parse_authenticated_message;
use crate::node::NodeInfo;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

fn main() -> std::io::Result<()> {
    let addr = "139.59.221.81:11625";
    let mut stream = TcpStream::connect(addr)?;

    let secret = stellar::SecretKey::from_encoding("SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73").unwrap();

    let node_info = NodeInfo::new(
        19,
        21,
        19,
        "v19.1.0".to_string(),
        Network::new(b"Public Global Stellar Network ; September 2015")
    );

    let mut conn = Connection::new(
        node_info,
        secret,
        0
    );

    let hello_msg = conn.create_hello_message();
    let auth_hello_msg = conn.authenticate_message(hello_msg);
    let xdr_auth_hello_msg = converter::get_xdr_from_authenticated_message(&auth_hello_msg).unwrap();
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
            let res = xdr_buffer_parse_authenticated_message(&readbuf);
            println!("value of res: {:?}", res);

        }
    }
}
