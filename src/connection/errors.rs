#![allow(dead_code)] //todo: remove after being tested and implemented

use crate::xdr_converter::Error as XDRError;
use substrate_stellar_sdk::types::StellarMessage;
use tokio::sync;

#[derive(Debug, Eq, PartialEq, err_derive::Error)]
pub enum Error {
    #[error(display = "Authentication Certification: Expired")]
    AuthCertExpired,

    #[error(display = "Authentication Certification: Not Found")]
    AuthCertNotFound,

    #[error(display = "Authentication Certification: Invalid")]
    AuthCertInvalid,

    #[error(display = "Connection: {}", _0)]
    ConnectionFailed(String),

    #[error(display = "Write: {}", _0)]
    WriteFailed(String),

    #[error(display = "Sent: {}", _0)]
    SendFailed(String),

    #[error(display = "Read: {}", _0)]
    ReadFailed(String),

    #[error(display = "No Response from Stellar Node")]
    NoResponse, // No data left in the buffer

    #[error(display = "Sequence num with the Auth message is different with remote sequence")]
    InvalidSequenceNumber,

    #[error(display = "Verify error: Invalid Hmac")]
    InvalidHmac,

    #[error(display = "Hmac: {:?}", _0)]
    HmacError(hmac::digest::MacError),

    #[error(display = "Undefined: {}", _0)]
    Undefined(String),

    #[error(display = "{:?}", _0)]
    XDRConversionError(XDRError),

    #[error(display = "The sender channel is not initialized.")]
    ChannelNotSet,
}

impl From<XDRError> for Error {
    fn from(e: XDRError) -> Self {
        Error::XDRConversionError(e)
    }
}

impl<T> From<sync::mpsc::error::SendError<T>> for Error {
    fn from(e: sync::mpsc::error::SendError<T>) -> Self {
        Error::SendFailed(e.to_string())
    }
}

impl<T> From<sync::broadcast::error::SendError<T>> for Error {
    fn from(e: sync::broadcast::error::SendError<T>) -> Self {
        Error::SendFailed(e.to_string())
    }
}
