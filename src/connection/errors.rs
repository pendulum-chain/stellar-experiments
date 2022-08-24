#![allow(dead_code)] //todo: remove after being tested and implemented

use crate::xdr_converter::Error as XDRError;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    AuthCertExpired,
    AuthCertNotFound,
    AuthCertInvalid,

    ConnectionFailed(String),
    WriteFailed(String),
    ReadFailed(String),
    NoResponse, // No data left in the buffer

    HmacError(hmac::digest::MacError),
    Undefined(String),
    XDRConversionError(XDRError)
}

impl From<XDRError> for Error {
    fn from(e: XDRError) -> Self {
        Error::XDRConversionError(e)
    }
}
