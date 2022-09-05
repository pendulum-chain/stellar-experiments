mod connector;
mod services;
mod flow_controller;

pub use connector::*;
pub use services::*;

type Xdr = Vec<u8>;

#[derive(Debug, Clone)]
enum Direction {
    ForStream,
    ForConnector,
}
