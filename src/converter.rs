#![allow(dead_code)] //todo: remove after being tested and implemented

use substrate_stellar_sdk::types::{AuthenticatedMessage, AuthenticatedMessageV0, HmacSha256Mac, MessageType, StellarMessage};
use substrate_stellar_sdk::{SecretKey, XdrCodec};

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    UsizeToU32ExceedMax,
    UnsupportedMessageVersion,
    DecodeError(String)
}


/// Returns XDR format of the message or
/// an error when the message length exceeds the max of u32
fn message_to_bytes<T: XdrCodec>(message:&T) -> Result<Vec<u8>, Error> {
    let mut message_xdr = message.to_xdr();

    // get the bytes of the message xdr's length.
    let message_len_bytes = u32::try_from(message_xdr.len())
        .map(|len| len.to_be_bytes())
        .map_err(|_| Error::UsizeToU32ExceedMax)?;

    let mut buffer: Vec<u8> = vec![];
    // first 4 bytes are for the length
    buffer.extend_from_slice(&message_len_bytes);
    // the message
    buffer.append(&mut message_xdr);

    Ok(buffer)
}

/// Returns xdr of the authenticated message
pub fn get_xdr_from_authenticated_message(message:&AuthenticatedMessage) -> Result<Vec<u8>, Error>  {
    message_to_bytes(message)
}

/// Returns xdr of the stellar message
pub fn get_xdr_from_stellar_message(message:&StellarMessage) -> Result<Vec<u8>, Error> {
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


#[cfg(test)]
mod test {
    use substrate_stellar_sdk::types::{MessageType, ScpEnvelope, StellarMessage};
    use substrate_stellar_sdk::XdrCodec;
    use crate::xdr_buffer_parse_authenticated_message;

    #[test]
    fn parse_hello_stellar_message_success() {
        let mut message = base64::decode_config(
            "AAAADQAAABMAAAAVAAAAE3rDOZdUTjF10ma9AiQ5sizbFlCMARY/JuXLKj4QRal5AAAAB3YxOS4xLjAAAAAtaQAAAACvC49kGL+ELaA8UrxHu2GhTlexuH6TmfWWzwOsKR2Ek2szUiNOwlIpFO6Q94sBXjIDxqIc7Yq1YOCJtNOG3EJeAAABgpDe25MAAABAiyWR0X9nBw489imdKbVQgLSe//8qS8PJ9jmqRUyKBf3nlUhsrlf8xI0gG/ndUrvGT6NkV/eZl85yi6tPIhF4CtOD4qij3KLBOwjXX0YFVtoLnCSGSHey+3CJW23AEqfy",
            base64::STANDARD,
        ).unwrap();

        let res = StellarMessage::from_xdr(&message);

        println!("THE STELLAR MESSAGE: {:?}",res);


    }
}