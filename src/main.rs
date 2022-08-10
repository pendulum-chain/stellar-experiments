mod connection;
pub mod node;
pub mod converter;


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
use crate::node::NodeInfo;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

fn main() -> std::io::Result<()> {
    let addr = "139.59.221.81:11625"; // SDF 1
    //let addr = "45.55.99.75:11625"; //LOBSTR 4 (Asia)
    let mut stream = TcpStream::connect(addr)?;

    let secret = stellar::SecretKey::from_encoding("SBLI7RKEJAEFGLZUBSCOFJHQBPFYIIPLBCKN7WVCWT4NEG2UJEW33N73").unwrap();

    let mut con_auth = connection::ConnectionAuth::new(
        Network::new(b"Public Global Stellar Network ; September 2015"),
        secret,
        0
    );

    let time_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let time_now = u64::try_from(time_now).unwrap();
    let _ = con_auth.generate_and_save_auth_cert(time_now);

    let node_info = NodeInfo::new(
        19,
        21,
        19,
        "v19.1.0".to_string(),
        Network::new(b"Public Global Stellar Network ; September 2015")
    );

    let mut conn = Connection::new(node_info,con_auth);

    let hello_msg = conn.create_hello_message();
    let auth_hello_msg = conn.authenticate_message(hello_msg);
    let xdr_auth_hello_msg = converter::xdr_buffer_from_authenticated_message(&auth_hello_msg).unwrap();
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
        //println!("THE READBUF AAA: {:?}", readbuf);
        if size > 0 {
            println!("--------------------------");

            println!("size: {}", size);
            let msg = &readbuf[..size];
            println!("msg: {:?}", msg);

            let message_version_xdr = &readbuf[..4];
            println!("message_version_xdr: {:?}", message_version_xdr);

            let sequence_number_xdr = &readbuf[4..12];
            println!("sequence_number_xdr: {:?}", sequence_number_xdr);
            let message_type_xdr = &readbuf[12..16];
            println!("message_type_xdr: {:?}", message_type_xdr);
            let mac_xdr = &readbuf[size-32..size];
            println!("mac_xdr: {:?}", mac_xdr);


            let response: AuthenticatedMessage = XdrCodec::from_xdr(&readbuf[4..size]).unwrap();
            //let response: StellarMessage = XdrCodec::from_xdr(stellar_message_xdr).unwrap();
            println!("response: {:?}", response);
            if let AuthenticatedMessage::V0(v0) = response {
                if let StellarMessage::ErrorMsg(e)= v0.message {
                    println!("error msg: {}", String::from_utf8_lossy(e.msg.get_vec()));
                }
            }
        }
    }
}
