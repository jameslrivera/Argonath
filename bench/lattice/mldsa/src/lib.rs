use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Verifier};

pub fn verify(pk_bytes: &[u8; 1312], sig: &[u8; 2420], msg: &[u8]) -> bool {
    match ml_dsa_44::PublicKey::try_from_bytes(*pk_bytes) {
        Ok(pk) => pk.verify(msg, sig, &[]),
        Err(_) => false,
    }
}
