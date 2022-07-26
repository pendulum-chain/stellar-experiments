
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use substrate_stellar_sdk::{Curve25519Secret, PublicKey, SecretKey, XdrCodec};
use substrate_stellar_sdk::types::{AuthCert, Curve25519Public, HmacSha256Mac, Signature, Uint256};

const crypto_scalarmult_BYTES:usize = 32; // https://docs.rs/libsodium-sys/latest/libsodium_sys/constant.crypto_scalarmult_BYTES.html
const ENV_TYPE_AUTH:Vec<u8> = b"envelopeTypeAuth".to_xdr();

pub struct ConnectionAuth {
    secret: Curve25519Secret,
    we_called_remote_shared_keys: HashMap<Curve25519Public,HmacSha256Mac>,
    remote_called_us_shared_keys: HashMap<Curve25519Public,HmacSha256Mac>
}

impl ConnectionAuth {
    // fn get_shared_key(&self, remote_pub_key:&Curve25519Public, secret_key:SecretKey, we_called_remote:bool) {
    //     let shared_key = if we_called_remote {
    //         &self.we_called_remote_shared_keys.get(remote_pub_key)
    //     } else {
    //         &self.remote_called_us_shared_keys.get(remote_pub_key)
    //     };
    //
    //     let mut buffer:Vec<u8> = vec![];
    //     if shared_key.is_none() {
    //         libsodium_sys::crypto_scalarmult(buffer,secret_key,remote_pub_key);
    //     }
    // }

}

fn create_auth_cert(network_id_xdr: &mut Vec<u8>, pub_key: &PublicKey, secret:&SecretKey) -> AuthCert {
    let time_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let auth_expiration_limit:u64 = 3600;
    let expiration = time_now + auth_expiration_limit;
    let mut expiration_xdr = expiration.to_xdr();



    let mut pub_key_xdr = pub_key.to_xdr();
    let mut buf:Vec<u8> = vec![];
    buf.append(network_id_xdr);
    buf.append(&mut ENV_TYPE_AUTH);
    buf.append(&mut expiration_xdr);
    buf.append(&mut pub_key_xdr);

    let signature:Signature = Signature::new(secret.create_signature(buf).to_vec()).unwrap();

    let pubkey = Curve25519Public{key: pub_key.into_binary()};

    AuthCert{
        pubkey,
        expiration,
        sig: signature
    }
}

fn verify_remote_auth_cert(time_in_secs:u64, remote_pub_key:&PublicKey, auth_cert: &AuthCert, network_id_xdr: &mut Vec<u8>) -> bool {
    let expiration = auth_cert.expiration;
    if expiration <= (time_in_secs / 1000) {
        return false;
    }

    let mut raw_sig_data: Vec<u8> = vec![];

    raw_sig_data.append(&mut ENV_TYPE_AUTH);
    raw_sig_data.append(&mut auth_cert.expiration.to_xdr());
    raw_sig_data.append(&mut auth_cert.pubkey.to_xdr());


    // aaaaaaah, why
    remote_pub_key.verify_signature(raw_sig_data,&auth_cert.sig.get_vec());

    true;
}

fn create_sending_mac_key(local_nonce:Uint256, remote_nonce:Uint256, remote_pub_key:Curve25519Public, we_called_remote:bool ) {
    let mut local_n = local_nonce.to_vec();
    let mut remote_n = remote_nonce.to_vec();

    let mut buf:Vec<u8> = vec![];

    if we_called_remote {
        buf.append(&mut vec![0]);
    } else {
        buf.append(&mut vec![1]);
    }

    buf.append(&mut local_n);
    buf.append(&mut remote_n);
    buf.append(&mut vec![1]);

}

#[cfg(test)]
mod test {
    use substrate_stellar_sdk::network::Network;
    use substrate_stellar_sdk::{SecretKey, XdrCodec};
    use crate::connection::create_auth_cert;

    #[test]
    fn create_valid_auth_cert() {
        let secret = SecretKey::from_encoding("SCV6Q3VU4S52KVNJOFXWTHFUPHUKVYK3UV2ISGRLIUH54UGC6OPZVK2D").expect("should be okay");
        let pub_key = secret.get_public();
        let public_network = substrate_stellar_sdk::network::Network::new(b"Public Global Stellar Network ; September 2015");

        create_auth_cert(
            &mut public_network.get_id().to_xdr(),
            pub_key,
            &secret
        );
    }
}