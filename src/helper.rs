use crate::connection::errors::Error;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};
use substrate_stellar_sdk::types::{HmacSha256Mac, Uint256};
use substrate_stellar_sdk::SecretKey;
type Buffer = [u8; 32];

// Create alias for HMAC-SHA256
pub type HmacSha256 = Hmac<Sha256>;

pub fn create_sha256_hmac(data_buffer: &[u8], mac_key_buffer: &Buffer) -> Option<HmacSha256Mac> {
    let res = HmacSha256::new_from_slice(mac_key_buffer)
        .map(|mut hmac| {
            hmac.update(data_buffer);

            let hmac = hmac.finalize().into_bytes().to_vec();

            HmacSha256Mac {
                mac: hmac.try_into().unwrap(),
            }
        })
        .ok();

    if res.is_none() {
        log::warn!("InvalidLength when converting the bufffer to sha256 hmac.");
    }
    res
}

pub fn verify_hmac(data_buffer: &[u8], mac_key_buffer: &Buffer, mac: &[u8]) -> Result<(), Error> {
    let mut hmac =
        HmacSha256::new_from_slice(mac_key_buffer).map_err(|_| Error::HmacInvalidLength)?;

    hmac.update(data_buffer);

    hmac.verify_slice(mac).map_err(|e| Error::HmacError(e))
}

/// Returns a new BigNumber with a pseudo-random value equal to or greater than 0 and less than 1.
pub fn generate_random_nonce() -> Uint256 {
    let mut rng = rand::thread_rng();
    let random_float = rng.gen_range(0.00..1.00);
    let mut hash = Sha256::new();
    hash.update(random_float.to_string());
    hash.finalize().to_vec().try_into().unwrap()
}

pub fn secret_key_binary(key: &str) -> [u8; 32] {
    let bytes = base64::decode_config(key, base64::STANDARD).unwrap();
    let secret_key = SecretKey::from_binary(bytes.try_into().unwrap());
    secret_key.into_binary()
}
