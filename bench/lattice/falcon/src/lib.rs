use fn_dsa_vrfy::{VerifyingKey, VerifyingKeyStandard, DOMAIN_NONE, HASH_ID_RAW};

pub fn verify(vk_bytes: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match VerifyingKeyStandard::decode(vk_bytes) {
        Some(vk) => vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, msg),
        None => false,
    }
}
