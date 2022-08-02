#![allow(dead_code)] //todo: remove after being tested and implemented


#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    AuthCertExpired,
    AuthCertNotFound,


}


