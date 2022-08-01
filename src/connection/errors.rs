#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    AuthCertExpired,
    AuthCertNotFound,
}
