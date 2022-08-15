#![allow(dead_code)] //todo: remove after being tested and implemented

use substrate_stellar_sdk::types::{
    AuthenticatedMessage, AuthenticatedMessageV0, HmacSha256Mac, MessageType, StellarMessage,
};
use substrate_stellar_sdk::{SecretKey, XdrCodec};

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    UsizeToU32ExceedMax,
    UnsupportedMessageVersion,
    DecodeError(String),
}

pub fn secret_key_binary(key: &str) -> [u8; 32] {
    let bytes = base64::decode_config(key, base64::STANDARD).unwrap();
    let secret_key = SecretKey::from_binary(bytes.try_into().unwrap());
    secret_key.into_binary()
}

/// Returns xdr of the authenticated message
pub fn from_authenticated_message(message: &AuthenticatedMessage) -> Result<Vec<u8>, Error> {
    message_to_bytes(message)
}

pub fn to_authenticated_message(xdr_message: &[u8]) -> Result<AuthenticatedMessageV0, Error> {
    let xdr_msg_len = xdr_message.len();

    let msg_vers = parse_message_version(&xdr_message[0..4])?;
    if msg_vers != 0 {
        return Err(Error::UnsupportedMessageVersion);
    }

    let sequence = parse_sequence(&xdr_message[4..12])?;

    // todo: this has to be consumed in the AuthenticatedMessageV0
    // let message_type = parse_message_type(&xdr_message[12..16])?;

    let message = parse_stellar_message(&xdr_message[16..(xdr_msg_len - 32)])?;

    let m = xdr_message[(xdr_msg_len - 32)..xdr_msg_len]
        .to_vec()
        .try_into()
        .unwrap();
    let mac = HmacSha256Mac { mac: m };

    Ok(AuthenticatedMessageV0 {
        sequence,
        message,
        mac,
    })
}

fn parse_stellar_message(xdr_message: &[u8]) -> Result<StellarMessage, Error> {
    StellarMessage::from_xdr(xdr_message)
        .map_err(|_| Error::DecodeError("StellarMessage".to_string()))
}

fn parse_message_version(xdr_message: &[u8]) -> Result<u32, Error> {
    u32::from_xdr(xdr_message).map_err(|_| Error::DecodeError("MessageVersion".to_string()))
}

fn parse_sequence(xdr_message: &[u8]) -> Result<u64, Error> {
    u64::from_xdr(xdr_message).map_err(|_| Error::DecodeError("SequenceNumber".to_string()))
}

fn parse_message_type(xdr_message: &[u8]) -> Result<MessageType, Error> {
    MessageType::from_xdr(xdr_message).map_err(|_| Error::DecodeError("MessageType".to_string()))
}

/// Returns XDR format of the message or
/// an error when the message length exceeds the max of u32
fn message_to_bytes<T: XdrCodec>(message: &T) -> Result<Vec<u8>, Error> {
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

#[cfg(test)]
mod test {

    use crate::xdr_converter::to_authenticated_message;

    #[test]
    fn parse_authenticated_message_success() {
        let msg = base64::decode_config(
            "AAAAAAAAAAAAAAA7AAAACwAAAACMHUtKNgEX1QDfz4zesWaxmhLg9Le806GgxemeQfaXmQAAAAACKDOuAAAAAzQaCq4p6tLHpdfwGhnlyX9dMUP70r4Dm98Td6YvKnhoAAAAAQAAAJg1D82tsvx59BI2BldZq12xYzdrhUkIflWnRwbiJsoMUgAAAABg4A0jAAAAAAAAAAEAAAAAUwoi9HcvJrwUn5w15omNdNffAJKoHHDdZh+2c+8VUd4AAABAB5/NoeG4iJJitcTDJvdhDLaLL9FSUHodRXvMEjbGKeDSkSXDgl+q+VvDXenwQNOOhLg112bsviGwh61ci4HnAgAAAAEAAACYNQ/NrbL8efQSNgZXWatdsWM3a4VJCH5Vp0cG4ibKDFIAAAAAYOANIwAAAAAAAAABAAAAAFMKIvR3Lya8FJ+cNeaJjXTX3wCSqBxw3WYftnPvFVHeAAAAQAefzaHhuIiSYrXEwyb3YQy2iy/RUlB6HUV7zBI2xing0pElw4Jfqvlbw13p8EDTjoS4Nddm7L4hsIetXIuB5wIAAABAyN92d7osuHXtUWHoEQzSRH5f9h6oEQAGK02b4CO4bQchmpbwbqGQLdbD9psFpamuLrDK+QJiBuKw3PVnMNlMDA9Ws6xvU3NyJ/OBsg2EZicl61zCYxrQXQ4Qq/eXI+wT",
            base64::STANDARD
        ).unwrap();

        //todo: once the authenticatedmessagev0 type is solved, continue the test
        let _ = to_authenticated_message(&msg);
    }
}
