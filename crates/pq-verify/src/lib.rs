#![cfg_attr(not(test), no_std)]

pub const N: usize = 32;
pub const W: usize = 16;
pub const LOG_W: usize = 4;
pub const LEN1: usize = 64;
pub const LEN2: usize = 3;
pub const LEN: usize = LEN1 + LEN2;

pub type Hash = [u8; N];

pub trait Hasher {
    fn hash(&self, parts: &[&[u8]]) -> Hash;
}

pub fn chain<H: Hasher>(h: &H, start: &Hash, steps: usize) -> Hash {
    let mut x = *start;
    let mut i = 0;
    while i < steps {
        x = h.hash(&[&x]);
        i += 1;
    }
    x
}

pub fn message_digits(digest: &Hash) -> [u8; LEN] {
    let mut out = [0u8; LEN];
    let mut i = 0;
    while i < LEN1 {
        let byte = digest[i / 2];
        let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
        out[i] = nibble;
        i += 1;
    }
    let mut checksum: u32 = 0;
    let mut j = 0;
    while j < LEN1 {
        checksum += (W as u32 - 1) - out[j] as u32;
        j += 1;
    }
    checksum <<= 8 - ((LEN2 * LOG_W) % 8);
    let mut k = 0;
    while k < LEN2 {
        let shift = LOG_W * (LEN2 - 1 - k);
        out[LEN1 + k] = ((checksum >> shift) & (W as u32 - 1)) as u8;
        k += 1;
    }
    out
}

pub fn public_key_from_signature<H: Hasher>(
    h: &H,
    digest: &Hash,
    signature: &[Hash; LEN],
) -> [Hash; LEN] {
    let digits = message_digits(digest);
    let mut tips = [[0u8; N]; LEN];
    let mut i = 0;
    while i < LEN {
        let steps = (W - 1) - digits[i] as usize;
        tips[i] = chain(h, &signature[i], steps);
        i += 1;
    }
    tips
}

pub fn compress<H: Hasher>(h: &H, tips: &[Hash; LEN]) -> Hash {
    let mut flat = [0u8; N * LEN];
    let mut i = 0;
    while i < LEN {
        let mut j = 0;
        while j < N {
            flat[i * N + j] = tips[i][j];
            j += 1;
        }
        i += 1;
    }
    h.hash(&[&flat])
}

pub fn verify<H: Hasher>(
    h: &H,
    digest: &Hash,
    signature: &[Hash; LEN],
    public_key_commitment: &Hash,
) -> bool {
    let tips = public_key_from_signature(h, digest, signature);
    let recovered = compress(h, &tips);
    ct_eq(&recovered, public_key_commitment)
}

pub fn xmss_root<H: Hasher>(h: &H, leaf: &Hash, leaf_index: u32, auth_path: &[Hash]) -> Hash {
    let mut node = *leaf;
    let mut index = leaf_index;
    let mut level = 0;
    while level < auth_path.len() {
        let sibling = &auth_path[level];
        node = if index & 1 == 0 {
            h.hash(&[&node, sibling])
        } else {
            h.hash(&[sibling, &node])
        };
        index >>= 1;
        level += 1;
    }
    node
}

fn ct_eq(a: &Hash, b: &Hash) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < N {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    struct Sha;
    impl Hasher for Sha {
        fn hash(&self, parts: &[&[u8]]) -> Hash {
            let mut hasher = Sha256::new();
            for p in parts {
                hasher.update(p);
            }
            let out = hasher.finalize();
            let mut h = [0u8; N];
            h.copy_from_slice(&out);
            h
        }
    }

    fn secret_key(seed: u8) -> [Hash; LEN] {
        let h = Sha;
        let mut sk = [[0u8; N]; LEN];
        let mut i = 0;
        while i < LEN {
            sk[i] = h.hash(&[&[seed], &[i as u8], b"wots-sk-seed"]);
            i += 1;
        }
        sk
    }

    fn public_key(sk: &[Hash; LEN]) -> Hash {
        let h = Sha;
        let mut tips = [[0u8; N]; LEN];
        let mut i = 0;
        while i < LEN {
            tips[i] = chain(&h, &sk[i], W - 1);
            i += 1;
        }
        compress(&h, &tips)
    }

    fn sign(sk: &[Hash; LEN], digest: &Hash) -> [Hash; LEN] {
        let h = Sha;
        let digits = message_digits(digest);
        let mut sig = [[0u8; N]; LEN];
        let mut i = 0;
        while i < LEN {
            sig[i] = chain(&h, &sk[i], digits[i] as usize);
            i += 1;
        }
        sig
    }

    #[test]
    fn sign_verify_roundtrip() {
        let h = Sha;
        let sk = secret_key(7);
        let pk = public_key(&sk);
        let digest = h.hash(&[b"forced withdrawal approval"]);
        let sig = sign(&sk, &digest);
        assert!(verify(&h, &digest, &sig, &pk));
    }

    #[test]
    fn rejects_tampered_signature() {
        let h = Sha;
        let sk = secret_key(3);
        let pk = public_key(&sk);
        let digest = h.hash(&[b"approve me"]);
        let mut sig = sign(&sk, &digest);
        sig[10][0] ^= 0x01;
        assert!(!verify(&h, &digest, &sig, &pk));
    }

    #[test]
    fn rejects_wrong_message() {
        let h = Sha;
        let sk = secret_key(5);
        let pk = public_key(&sk);
        let d1 = h.hash(&[b"message one"]);
        let d2 = h.hash(&[b"message two"]);
        let sig = sign(&sk, &d1);
        assert!(!verify(&h, &d2, &sig, &pk));
    }

    #[test]
    fn xmss_auth_path_recovers_root() {
        let h = Sha;
        let leaves: [Hash; 4] = [
            h.hash(&[b"leaf0"]),
            h.hash(&[b"leaf1"]),
            h.hash(&[b"leaf2"]),
            h.hash(&[b"leaf3"]),
        ];
        let n01 = h.hash(&[&leaves[0], &leaves[1]]);
        let n23 = h.hash(&[&leaves[2], &leaves[3]]);
        let root = h.hash(&[&n01, &n23]);
        let recovered = xmss_root(&h, &leaves[2], 2, &[leaves[3], n01]);
        assert_eq!(recovered, root);
    }
}
