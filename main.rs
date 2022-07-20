use std::io::prelude::*;
use std::net::TcpStream;

use stellar::{PublicKey, XdrCodec, Curve25519Secret};
use stellar::compound_types::LimitedString;
use stellar::types::{Curve25519Public, AuthCert, Hello, Auth, Signature, Uint256, StellarMessage, Error, AuthenticatedMessage, AuthenticatedMessageV0, HmacSha256Mac, SendMore};
use substrate_stellar_sdk as stellar;

fn main() -> std::io::Result<()> {
    //let addr = "139.59.221.81:11625"; //LOBSTR 4 (Asia)
    let addr = "54.173.54.200:11625"; // SDF 1
    let mut stream = TcpStream::connect(addr)?;
    
    let secret = stellar::SecretKey::from_binary([0; 32]);
    let public = secret.get_public();

    //hello handshake
    let hello = Hello{ 
        ledger_version: 17, 
        overlay_version: 17, 
        overlay_min_version: 16, 
        network_id: *stellar::network::TEST_NETWORK.get_id(), 
        version_str: LimitedString::<100>::new("v15.0.0".as_bytes().to_vec()).unwrap(), 
        listening_port: 11625, 
        peer_id: public.clone(),
        cert: AuthCert{ 
            pubkey: Curve25519Public{key: public.clone().into_binary()}, 
            expiration: 0,
            sig: Signature::new(secret.create_signature([0;32]).to_vec()).unwrap(),
        }, 
        nonce: [0;32], 
    };

    //force error by sending unexpected xdr
    // let buf = XdrCodec::to_xdr(&StellarMessage::Hello(hello));
    // stream.write(&buf)?;

    //send hello message
    let authenticated_message = AuthenticatedMessage::V0(AuthenticatedMessageV0 { 
        sequence: 0, 
        message: StellarMessage::Hello(hello.clone()), 
        mac: HmacSha256Mac{
            mac: [0;32],
        }
    });
    let buf = XdrCodec::to_xdr(&authenticated_message);
    stream.write(&buf)?;



    //request a message
    // let sendmore = SendMore{num_messages: 1 };
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
