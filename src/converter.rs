#![allow(dead_code)] //todo: remove after being tested and implemented

use substrate_stellar_sdk::types::{AuthenticatedMessage, AuthenticatedMessageV0, HmacSha256Mac, MessageType, StellarMessage};
use substrate_stellar_sdk::{SecretKey, XdrCodec};

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    UsizeToU32ExceedMax,
    UnsupportedMessageVersion,
    DecodeError(String)
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


fn xdr_buffer_parse_message_version(xdr_message:&[u8]) -> Result<u32,Error> {
    u32::from_xdr(xdr_message)
        .map_err(|_| Error::DecodeError("MessageVersion".to_string()))
}

fn xdr_buffer_parse_sequence(xdr_message:&[u8]) -> Result<u64, Error> {
    u64::from_xdr(xdr_message).map_err(|_| Error::DecodeError("SequenceNumber".to_string()))
}

fn xdr_buffer_parse_message_type(xdr_message:&[u8]) -> Result<MessageType, Error> {
   MessageType::from_xdr(xdr_message)
       .map_err(|_| Error::DecodeError("MessageType".to_string()))
}

fn xdr_buffer_parse_stellar_message(xdr_message:&[u8]) -> Result<StellarMessage, Error> {
    StellarMessage::from_xdr(xdr_message)
        .map_err(|_| Error::DecodeError("StellarMessage".to_string()))
}

pub fn xdr_buffer_parse_authenticated_message(xdr_message:&[u8]) -> Result<AuthenticatedMessageV0,Error> {
    let xdr_msg_len = xdr_message.len();

    let msg_vers = xdr_buffer_parse_message_version(&xdr_message[0..4])?;
    if msg_vers != 0 {
        return Err(Error::UnsupportedMessageVersion);
    }

    let sequence = xdr_buffer_parse_sequence(&xdr_message[4..12])?;
    let message_type = xdr_buffer_parse_message_type(&xdr_message[12..16])?;

    let message = xdr_buffer_parse_stellar_message(&xdr_message[16..(xdr_msg_len - 32)])?;

    let m = xdr_message[(xdr_msg_len - 32)..xdr_msg_len].to_vec().try_into().unwrap();
    let mac = HmacSha256Mac {
        mac: m
    };

    Ok(AuthenticatedMessageV0 {
        sequence,
        message,
        mac
    })
}

pub fn secret_key_binary(key:&str) -> [u8;32] {
    let bytes = base64::decode_config(key, base64::STANDARD).unwrap();
    let secret_key = SecretKey::from_binary(bytes.try_into().unwrap());
    secret_key.into_binary()
}