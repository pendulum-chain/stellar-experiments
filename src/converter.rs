#![allow(dead_code)] //todo: remove after being tested and implemented

use substrate_stellar_sdk::types::{AuthenticatedMessage, StellarMessage};
use substrate_stellar_sdk::XdrCodec;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    UsizeToU32ExceedMax,
    DecodeError,
    UnsupportedMessageVersion
}

fn to_bytes<T: XdrCodec>(xdr:&T) -> Result<[u8;4], Error>{
    u32::try_from(xdr.to_xdr().len())
        .map(|len| len.to_be_bytes())
        .map_err(|_| Error::UsizeToU32ExceedMax)
}

fn message_to_bytes<T: XdrCodec>(message:&T) -> Result<Vec<u8>, Error> {
    to_bytes(message)
        .map(|bytes| {
            let mut buffer: Vec<u8> = vec![];
            buffer.extend_from_slice(&bytes);
            buffer.append(&mut message.to_xdr());
            buffer
        })
}


pub fn xdr_buffer_from_authenticated_message(message:&AuthenticatedMessage) -> Result<Vec<u8>, Error>  {
    message_to_bytes(message)
}

pub fn xdr_buffer_from_stellar_message(message:&StellarMessage) -> Result<Vec<u8>, Error> {
    message_to_bytes(message)
}


// pub fn xdr_buffer_parse_message_version(xdr_message:&[u8]) {
//     let res = u32::from_xdr(xdr_message)
//         .map_err();
//
//
// }

// pub fn xdr_buffer_parse_authenticated_message(xdr_message:&[u8]) {
//     let message_version_xdr = xdr_message[..4];
//
//     u32::from_xdr(message_version_xdr);
//
//     println!("message_version_xdr: {:?}", message_version_xdr);
// }