use crate::helper::create_sha256_hmac;
use substrate_stellar_sdk::types::{HmacSha256Mac, Uint256};

pub struct HMacKeys {
    sending: HmacSha256Mac,
    receiving: HmacSha256Mac,
}

impl HMacKeys {
    pub fn new(
        shared_key: &HmacSha256Mac,
        local_nonce: Uint256,
        remote_nonce: Uint256,
        remote_called_us: bool,
    ) -> Self {
        let sending =
            create_sending_mac_key(&shared_key, local_nonce, remote_nonce, !remote_called_us);

        let receiving =
            create_receiving_mac_key(&shared_key, local_nonce, remote_nonce, !remote_called_us);

        HMacKeys { sending, receiving }
    }

    pub fn sending(&self) -> &HmacSha256Mac {
        &self.sending
    }

    pub fn receiving(&self) -> &HmacSha256Mac {
        &self.receiving
    }
}

pub fn create_sending_mac_key(
    shared_key: &HmacSha256Mac,
    local_nonce: Uint256,
    remote_nonce: Uint256,
    we_called_remote: bool,
) -> HmacSha256Mac {
    let mut buf: Vec<u8> = vec![];

    if we_called_remote {
        buf.append(&mut vec![0]);
    } else {
        buf.append(&mut vec![1]);
    }

    let mut local_n = local_nonce.to_vec();
    let mut remote_n = remote_nonce.to_vec();

    buf.append(&mut local_n);
    buf.append(&mut remote_n);
    buf.append(&mut vec![1]);

    create_sha256_hmac(&buf, &shared_key.mac).unwrap_or(HmacSha256Mac { mac: [0; 32] })
}

pub fn create_receiving_mac_key(
    shared_key: &HmacSha256Mac,
    local_nonce: Uint256,
    remote_nonce: Uint256,
    we_called_remote: bool,
) -> HmacSha256Mac {
    let mut buf: Vec<u8> = vec![];

    if we_called_remote {
        buf.append(&mut vec![1]);
    } else {
        buf.append(&mut vec![0]);
    }

    let mut local_n = local_nonce.to_vec();
    let mut remote_n = remote_nonce.to_vec();

    buf.append(&mut remote_n);
    buf.append(&mut local_n);
    buf.append(&mut vec![1]);

    create_sha256_hmac(&buf, &shared_key.mac).unwrap_or(HmacSha256Mac { mac: [0; 32] })
}
