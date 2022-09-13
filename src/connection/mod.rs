pub mod async_ops;
mod authentication;
pub mod errors;
mod flow_controller;
mod handshake;
mod hmac;

pub use authentication::*;
pub use handshake::*;
use substrate_stellar_sdk::SecretKey;

pub struct Config {
    address: String,
    port: u32,
    secret_key: SecretKey,
    pub auth_cert_expiration: u64,
    pub recv_tx_msgs: bool,
    pub recv_scp_messages: bool,
    pub remote_called_us: bool,
}

impl Config {
    pub fn new(
        addr: &str,
        port: u32,
        secret_key: SecretKey,
        auth_cert_expiration: u64,
        recv_tx_msgs: bool,
        recv_scp_messages: bool,
        remote_called_us: bool,
    ) -> Config {
        Config {
            address: addr.to_owned(),
            port,
            secret_key,
            auth_cert_expiration,
            recv_tx_msgs,
            recv_scp_messages,
            remote_called_us,
        }
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }

    pub fn keypair(&self) -> SecretKey {
        self.secret_key.clone()
    }
}
