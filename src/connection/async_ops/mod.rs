mod config;
mod connector;

pub use config::*;
pub use connector::*;

type Xdr = Vec<u8>;

#[derive(Debug, Clone)]
enum Direction {
    ForStream,
    ForConnector,
}
