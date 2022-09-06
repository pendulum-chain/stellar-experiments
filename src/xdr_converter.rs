#![allow(dead_code)] //todo: remove after being tested and implemented

use base64::DecodeError;
use std::fmt::Debug;
use substrate_stellar_sdk::types::{
    AuthenticatedMessage, AuthenticatedMessageV0, DontHave, HmacSha256Mac, MessageType,
    StellarMessage,
};
use substrate_stellar_sdk::{SecretKey, XdrCodec};
use thiserror::Error;

#[derive(Debug, Eq, PartialEq, err_derive::Error)]
pub enum Error {
    #[error(display = "Data more than the max of U32")]
    UsizeToU32ExceedMax,

    #[error(display = "Message Version: Unsupported")]
    UnsupportedMessageVersion,

    #[error(display = "Decode Error: {}", _0)]
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

/// To easily convert a message into a StellarMessage
macro_rules! _stellar_message {
    (&$ref:ident, $struct_str:ident) => {{
        use crate::xdr_converter::log_decode_error;
        use substrate_stellar_sdk::types::$struct_str;
        use substrate_stellar_sdk::XdrCodec;

        let ret: Result<StellarMessage, Error> = $struct_str::from_xdr($ref)
            .map(|msg| StellarMessage::$struct_str(msg))
            .map_err(|e| log_decode_error(stringify!($struct_str), e));

        ret
    }};
}

pub fn parse_authenticated_message(
    xdr_message: &[u8],
) -> Result<(AuthenticatedMessageV0, MessageType), Error> {
    let xdr_msg_len = xdr_message.len();

    let msg_vers = parse_message_version(&xdr_message[0..4])?;
    if msg_vers != 0 {
        return Err(Error::UnsupportedMessageVersion);
    }

    let msg_type = parse_message_type(&xdr_message[12..16])?;

    Ok((
        AuthenticatedMessageV0 {
            sequence: parse_sequence(&xdr_message[4..12])?,
            message: parse_stellar_message(&xdr_message[12..(xdr_msg_len - 32)])?,
            mac: parse_hmac(&xdr_message[(xdr_msg_len - 32)..xdr_msg_len])?,
        },
        msg_type,
    ))
}

pub fn get_message_length(data: &[u8]) -> u32 {
    if data.len() < 4 {
        return 0;
    }

    let mut message_len = data[0..4].to_vec();
    message_len[0] &= 0x7f;


    let res = u32::from_be_bytes(message_len.try_into().unwrap());
    res
}

pub fn  is_xdr_complete_message(data:&[u8], message_len:usize) -> bool {
    return data.len() - 4 >= message_len
}

pub fn get_message(data:&[u8], message_len:usize) -> (Vec<u8>, Vec<u8>) {
    (
        data[4..(message_len + 4)].to_owned(),
        data[0..(message_len + 4)].to_owned()
    )
}


fn log_decode_error<T: Debug>(source: &str, error: T) -> Error {
    println!("Decode Error of {}: {:?}", source, error);
    Error::DecodeError(source.to_string())
}

fn parse_stellar_message(xdr_message: &[u8]) -> Result<StellarMessage, Error> {
    StellarMessage::from_xdr(xdr_message).map_err(|e| log_decode_error("StellarMessage", e))
}

fn parse_message_version(xdr_message: &[u8]) -> Result<u32, Error> {
    u32::from_xdr(xdr_message).map_err(|e| log_decode_error("Message Version", e))
}

fn parse_sequence(xdr_message: &[u8]) -> Result<u64, Error> {
    u64::from_xdr(xdr_message).map_err(|e| log_decode_error("Sequence", e))
}

fn parse_hmac(xdr_message: &[u8]) -> Result<HmacSha256Mac, Error> {
    HmacSha256Mac::from_xdr(xdr_message).map_err(|e| log_decode_error("Hmac", e))
}

fn parse_message_type(xdr_message: &[u8]) -> Result<MessageType, Error> {
    MessageType::from_xdr(&xdr_message).map_err(|e| log_decode_error("Message Type", e))
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
    use crate::xdr_converter::{get_message_length, parse_authenticated_message, Error, is_xdr_complete_message, get_message};
    use substrate_stellar_sdk::types::StellarMessage;

    #[test]
    fn get_message_length_success() {
        let arr: [u8; 4] = [128, 0, 1, 28];

        assert_eq!(get_message_length(&arr), 284);
    }

    #[test]
    fn parse_authenticated_message_success() {
        let msg = base64::decode_config(
            "AAAAAAAAAAAAAAA7AAAACwAAAACMHUtKNgEX1QDfz4zesWaxmhLg9Le806GgxemeQfaXmQAAAAACKDOuAAAAAzQaCq4p6tLHpdfwGhnlyX9dMUP70r4Dm98Td6YvKnhoAAAAAQAAAJg1D82tsvx59BI2BldZq12xYzdrhUkIflWnRwbiJsoMUgAAAABg4A0jAAAAAAAAAAEAAAAAUwoi9HcvJrwUn5w15omNdNffAJKoHHDdZh+2c+8VUd4AAABAB5/NoeG4iJJitcTDJvdhDLaLL9FSUHodRXvMEjbGKeDSkSXDgl+q+VvDXenwQNOOhLg112bsviGwh61ci4HnAgAAAAEAAACYNQ/NrbL8efQSNgZXWatdsWM3a4VJCH5Vp0cG4ibKDFIAAAAAYOANIwAAAAAAAAABAAAAAFMKIvR3Lya8FJ+cNeaJjXTX3wCSqBxw3WYftnPvFVHeAAAAQAefzaHhuIiSYrXEwyb3YQy2iy/RUlB6HUV7zBI2xing0pElw4Jfqvlbw13p8EDTjoS4Nddm7L4hsIetXIuB5wIAAABAyN92d7osuHXtUWHoEQzSRH5f9h6oEQAGK02b4CO4bQchmpbwbqGQLdbD9psFpamuLrDK+QJiBuKw3PVnMNlMDA9Ws6xvU3NyJ/OBsg2EZicl61zCYxrQXQ4Qq/eXI+wT",
            base64::STANDARD
        ).unwrap();

        //todo: once the authenticatedmessagev0 type is solved, continue the test
        let _ = parse_authenticated_message(&msg);
    }

    #[test]
    fn message_not_complete_check() {

        let xdr_no_next_msg = base64::decode_config(
            "gAABaAAAAAAAAAAAAAAAAgAAAAsAAAAAAsUlnka7dHFfp69mUW6kEQ18IpsXLwcYk6yphpesUysAAAAAAULT7wAAAAN1tE4FkHboorc8QsJU7+LkIN2zbNK9MrkY49OpVcEzDwAAAAIAAAAw/0TiDQ==",
            base64::STANDARD
        ).unwrap();

        let len = get_message_length(&xdr_no_next_msg);

        let len = usize::try_from(len).unwrap();
        assert!(!is_xdr_complete_message(&xdr_no_next_msg,len ));
    }

    #[test]
    fn message_complete() {
        let xdr_has_next_msg = base64::decode_config(
            "gAAANAAAAAAAAAAAAAAAAAAAAAIAAAAAv2qE3dixC3UHHZmFXQGPliZ90ghxAiO5C4fYG/G4EeqAAANUAAAAAAAAAAAAAAABAAAABQAAADIAAAAAqTm9CAAALWkAAAAAAAAAAKkvb34AAC1pAAAAAAAAAAA23YxJAAAtaQAAAAAAAAAANDdVmQAALWkAAAAAAAAAAKkzSDUAAC1pAAAAAAAAAACer1MIAAAtaQAAAAAAAAAAI8ZHBAAALWkAAAAAAAAAACPGQFcAAC1pAAAAAAAAAACCxkWYAAAtaQAAAAAAAAAAaxSf6AAALWkAAAAAAAAAACv/s4IAAC1pAAAAAAAAAAA2TpjFAAAtaQAAAAAAAAAAsj7l8gAALWkAAAAAAAAAALhIZ40AAC1pAAAAAAAAAACeQEz9AAAtaQAAAAAAAAAAq2DFJwAALWkAAAAAAAAAADZKcDEAAC1pAAAAAAAAAAAnPPzbAAAtaQAAAAAAAAAAcyEZJgAALWkAAAAAAAAAACm+Dn4AAC1pAAAAAAAAAAB04vMyAAAtaQAAAAAAAAAANk4tVQAALWkAAAAAAAAAANRcdnwAAC1pAAAAAAAAAAB9J5EIAAAtaQAAAAAAAAAApeOhygAALWkAAAAAAAAAAK4kOPYAAC1pAAAAAAAAAABnC1mkAAAtaQAAAAAAAAAANqo7KwAALWkAAAAAAAAAADRO0w0AAC1pAAAAAAAAAAABtNQAAAAtaQAAAAAAAAAAcm+nvgAALWkAAAAAAAAAALS/SCYAAC1pAAAAAAAAAAA2SvPwAAAtaQAAAAAAAAAANpKzmAAALWkAAAAAAAAAAJ5VSogAAC1pAAAAAAAAAACyotgHAAAtaQAAAAAAAAAANkoQ2wAALWkAAAAAAAAAADZOAFMAAC1pAAAAAAAAAAA2qm9GAAAtaQAAAAAAAAAANpvTAgAALWkAAAAAAAAAAG/GQiEAAC1pAAAAAAAAAAAju7lmAAAtaQAAAAAAAAAANk7rHwAALWkAAAAAAAAAABfyLQ0AAC1pAAAAAAAAAAA2TjaRAAAtaQAAAAAAAAAANk5J7gAALWkAAAAAAAAAAHRm84QAAC1pAAAAAAAAAAAr/7KvAAAtaQAAAAAAAAAAufEGsgAALWkAAAAAAAAAADZOzt4AAC1pAAAAADKjiRSHBdyaVK1C+7UoMAGGyLJ5D1CjOi7gsns2GEFBgAABaAAAAAAAAAAAAAAAAgAAAAsAAAAAAsUlnka7dHFfp69mUW6kEQ18IpsXLwcYk6yphpesUysAAAAAAULT7wAAAAN1tE4FkHboorc8QsJU7+LkIN2zbNK9MrkY49OpVcEzDwAAAAIAAAAw/0TiDQ==",
            base64::STANDARD
        ).unwrap();

        let len = get_message_length(&xdr_has_next_msg);
        let len = usize::try_from(len).unwrap();

        let (nxt_msg, remaining) = get_message(&xdr_has_next_msg,len);

        let str= base64::encode(nxt_msg);
        assert_eq!(&str,"AAAAAAAAAAAAAAAAAAAAAgAAAAC/aoTd2LELdQcdmYVdAY+WJn3SCHECI7kLh9gb8bgR6g==");



    }

}
