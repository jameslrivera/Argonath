#![no_std]

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

pub const N: usize = 256;
pub const K: usize = 4;
pub const L: usize = 4;
pub const Q: i32 = 8_380_417;
pub const QINV: i32 = 58_728_449;
pub const D: u32 = 13;
pub const TAU: usize = 39;
pub const GAMMA1: i32 = 1 << 17;
pub const GAMMA2: i32 = (Q - 1) / 88;
pub const BETA: i32 = 78;
pub const OMEGA: usize = 80;

pub const SEED_BYTES: usize = 32;
pub const CTILDE_BYTES: usize = 32;
pub const MU_BYTES: usize = 64;
pub const POLYT1_PACKED: usize = 320;
pub const POLYZ_PACKED: usize = 576;
pub const POLYW1_PACKED: usize = 192;
pub const HINT_BYTES: usize = OMEGA + K;
pub const PK_BYTES: usize = SEED_BYTES + K * POLYT1_PACKED;
pub const SIG_BYTES: usize = CTILDE_BYTES + L * POLYZ_PACKED + HINT_BYTES;

pub type Poly = [i32; N];

const F_INV256_MONT: i32 = 41_978;

const ZETAS: [i32; N] = [
    -4186625, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
    1826347, 2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103,
    2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549,
    -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005,
    2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439,
    -3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
    -1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596,
    811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
    -3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221,
    -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
    -671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430,
    -3343383, 264944, 508951, 3097992, 44288, -1100098, 904516, 3958618,
    -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
    189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330,
    1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961,
    2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462,
    266997, 2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378,
    900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500,
    -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838,
    342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044,
    2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974,
    -3767016, 1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970,
    -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642,
    -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031,
    -542412, -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993,
    -2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
    -3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
    -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078,
    -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893,
    -2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
    -554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782,
];

#[inline(always)]
pub fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(QINV);
    ((a - (t as i64) * (Q as i64)) >> 32) as i32
}

#[inline(always)]
pub fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * Q
}

#[inline(always)]
pub fn caddq(a: i32) -> i32 {
    a + ((a >> 31) & Q)
}

pub fn ntt(a: &mut Poly) {
    let mut k = 0usize;
    let mut len = 128usize;
    while len > 0 {
        let mut start = 0usize;
        while start < N {
            k += 1;
            let zeta = ZETAS[k] as i64;
            for j in start..start + len {
                let t = montgomery_reduce(zeta * a[j + len] as i64);
                a[j + len] = a[j] - t;
                a[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

pub fn invntt_tomont(a: &mut Poly) {
    let mut k = N;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            k -= 1;
            let zeta = -(ZETAS[k] as i64);
            for j in start..start + len {
                let t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = montgomery_reduce(zeta * a[j + len] as i64);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in a.iter_mut() {
        *c = montgomery_reduce(F_INV256_MONT as i64 * *c as i64);
    }
}

pub fn pointwise_mont(out: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        out[i] = montgomery_reduce(a[i] as i64 * b[i] as i64);
    }
}

pub fn pointwise_acc_mont(acc: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        acc[i] += montgomery_reduce(a[i] as i64 * b[i] as i64);
    }
}

pub fn expand_a_poly(out: &mut Poly, rho: &[u8; SEED_BYTES], r: u8, s: u8) {
    let mut h = Shake128::default();
    h.update(rho);
    h.update(&[s, r]);
    let mut reader = h.finalize_xof();
    let mut buf = [0u8; 168];
    let mut filled = 0usize;
    while filled < N {
        reader.read(&mut buf);
        let mut pos = 0usize;
        while pos + 3 <= buf.len() && filled < N {
            let t = (buf[pos] as u32) | ((buf[pos + 1] as u32) << 8) | (((buf[pos + 2] & 0x7f) as u32) << 16);
            pos += 3;
            if (t as i32) < Q {
                out[filled] = t as i32;
                filled += 1;
            }
        }
    }
}

pub fn pk_tr(pk: &[u8]) -> [u8; MU_BYTES] {
    let mut h = Shake256::default();
    h.update(pk);
    let mut out = [0u8; MU_BYTES];
    h.finalize_xof().read(&mut out);
    out
}

pub fn message_mu(tr: &[u8; MU_BYTES], msg: &[u8]) -> [u8; MU_BYTES] {
    let mut h = Shake256::default();
    h.update(tr);
    h.update(&[0u8, 0u8]);
    h.update(msg);
    let mut out = [0u8; MU_BYTES];
    h.finalize_xof().read(&mut out);
    out
}

pub fn sample_in_ball(out: &mut Poly, ctilde: &[u8; CTILDE_BYTES]) {
    let mut h = Shake256::default();
    h.update(ctilde);
    let mut reader = h.finalize_xof();
    let mut head = [0u8; 8];
    reader.read(&mut head);
    let mut signs = u64::from_le_bytes(head);
    for c in out.iter_mut() {
        *c = 0;
    }
    let mut byte = [0u8; 1];
    for i in (N - TAU)..N {
        let j = loop {
            reader.read(&mut byte);
            if (byte[0] as usize) <= i {
                break byte[0] as usize;
            }
        };
        out[i] = out[j];
        out[j] = 1 - 2 * ((signs & 1) as i32);
        signs >>= 1;
    }
}

pub fn unpack_t1(out: &mut Poly, a: &[u8]) {
    for i in 0..N / 4 {
        let b = &a[5 * i..5 * i + 5];
        out[4 * i] = ((b[0] as i32) | ((b[1] as i32) << 8)) & 0x3ff;
        out[4 * i + 1] = (((b[1] as i32) >> 2) | ((b[2] as i32) << 6)) & 0x3ff;
        out[4 * i + 2] = (((b[2] as i32) >> 4) | ((b[3] as i32) << 4)) & 0x3ff;
        out[4 * i + 3] = (((b[3] as i32) >> 6) | ((b[4] as i32) << 2)) & 0x3ff;
    }
}

pub fn unpack_z(out: &mut Poly, a: &[u8]) {
    for i in 0..N / 4 {
        let b = &a[9 * i..9 * i + 9];
        let mut r0 = (b[0] as i32) | ((b[1] as i32) << 8) | ((b[2] as i32) << 16);
        r0 &= 0x3ffff;
        let mut r1 = ((b[2] as i32) >> 2) | ((b[3] as i32) << 6) | ((b[4] as i32) << 14);
        r1 &= 0x3ffff;
        let mut r2 = ((b[4] as i32) >> 4) | ((b[5] as i32) << 4) | ((b[6] as i32) << 12);
        r2 &= 0x3ffff;
        let mut r3 = ((b[6] as i32) >> 6) | ((b[7] as i32) << 2) | ((b[8] as i32) << 10);
        r3 &= 0x3ffff;
        out[4 * i] = GAMMA1 - r0;
        out[4 * i + 1] = GAMMA1 - r1;
        out[4 * i + 2] = GAMMA1 - r2;
        out[4 * i + 3] = GAMMA1 - r3;
    }
}

pub fn norm_ok(a: &Poly, bound: i32) -> bool {
    if bound > (Q - 1) / 8 {
        return false;
    }
    for &c in a.iter() {
        let t = c >> 31;
        let t = c - (t & (2 * c));
        if t >= bound {
            return false;
        }
    }
    true
}

pub fn hints_valid(h: &[u8]) -> bool {
    if h.len() != HINT_BYTES {
        return false;
    }
    let mut k = 0usize;
    for i in 0..K {
        let end = h[OMEGA + i] as usize;
        if end < k || end > OMEGA {
            return false;
        }
        for j in k..end {
            if j > k && h[j] <= h[j - 1] {
                return false;
            }
        }
        k = end;
    }
    h[k..OMEGA].iter().all(|&b| b == 0)
}

#[inline(always)]
fn decompose(a: i32) -> (i32, i32) {
    let mut a1 = (a + 127) >> 7;
    a1 = (a1 * 11_275 + (1 << 23)) >> 24;
    a1 ^= ((43 - a1) >> 31) & a1;
    let mut a0 = a - a1 * 2 * GAMMA2;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
    (a1, a0)
}

#[inline(always)]
fn use_hint(a: i32, hint: bool) -> i32 {
    let (a1, a0) = decompose(a);
    if !hint {
        return a1;
    }
    if a0 > 0 {
        if a1 == 43 { 0 } else { a1 + 1 }
    } else if a1 == 0 {
        43
    } else {
        a1 - 1
    }
}

pub fn use_hint_poly(w: &mut Poly, h: &[u8], row: usize) {
    let start = if row == 0 { 0 } else { h[OMEGA + row - 1] as usize };
    let end = h[OMEGA + row] as usize;
    let mut hinted = [false; N];
    for &pos in &h[start..end] {
        hinted[pos as usize] = true;
    }
    for i in 0..N {
        w[i] = use_hint(w[i], hinted[i]);
    }
}

pub fn pack_w1(out: &mut [u8], w1: &Poly) {
    for i in 0..N / 4 {
        out[3 * i] = (w1[4 * i] | (w1[4 * i + 1] << 6)) as u8;
        out[3 * i + 1] = ((w1[4 * i + 1] >> 2) | (w1[4 * i + 2] << 4)) as u8;
        out[3 * i + 2] = ((w1[4 * i + 2] >> 4) | (w1[4 * i + 3] << 2)) as u8;
    }
}

pub fn final_challenge(mu: &[u8; MU_BYTES], w1_enc: &[u8]) -> [u8; CTILDE_BYTES] {
    let mut h = Shake256::default();
    h.update(mu);
    h.update(w1_enc);
    let mut out = [0u8; CTILDE_BYTES];
    h.finalize_xof().read(&mut out);
    out
}

pub fn sig_ctilde(sig: &[u8]) -> &[u8] {
    &sig[..CTILDE_BYTES]
}
pub fn sig_z(sig: &[u8], i: usize) -> &[u8] {
    let off = CTILDE_BYTES + i * POLYZ_PACKED;
    &sig[off..off + POLYZ_PACKED]
}
pub fn sig_hints(sig: &[u8]) -> &[u8] {
    &sig[CTILDE_BYTES + L * POLYZ_PACKED..]
}
pub fn pk_rho(pk: &[u8]) -> &[u8] {
    &pk[..SEED_BYTES]
}
pub fn pk_t1(pk: &[u8], i: usize) -> &[u8] {
    let off = SEED_BYTES + i * POLYT1_PACKED;
    &pk[off..off + POLYT1_PACKED]
}

pub fn prepare_z(out: &mut Poly, sig: &[u8], i: usize) -> bool {
    unpack_z(out, sig_z(sig, i));
    if !norm_ok(out, GAMMA1 - BETA) {
        return false;
    }
    ntt(out);
    true
}

pub fn prepare_t1(out: &mut Poly, pk: &[u8], i: usize) {
    unpack_t1(out, pk_t1(pk, i));
    for c in out.iter_mut() {
        *c <<= D;
    }
    ntt(out);
}

pub fn prepare_c(out: &mut Poly, sig: &[u8]) {
    let mut ct = [0u8; CTILDE_BYTES];
    ct.copy_from_slice(sig_ctilde(sig));
    sample_in_ball(out, &ct);
    ntt(out);
}

pub fn poly(flat: &[i32], i: usize) -> &Poly {
    flat[i * N..(i + 1) * N].try_into().unwrap()
}

pub fn poly_mut(flat: &mut [i32], i: usize) -> &mut Poly {
    (&mut flat[i * N..(i + 1) * N]).try_into().unwrap()
}

pub fn compute_row(
    w: &mut Poly,
    a_row: &[i32],
    z_hat: &[i32],
    c_hat: &Poly,
    t1_hat_row: &Poly,
    hints: &[u8],
    row: usize,
    w1_out: &mut [u8],
) {
    for c in w.iter_mut() {
        *c = 0;
    }
    for s in 0..L {
        pointwise_acc_mont(w, poly(a_row, s), poly(z_hat, s));
    }
    for i in 0..N {
        let ct = montgomery_reduce(c_hat[i] as i64 * t1_hat_row[i] as i64);
        w[i] = reduce32(w[i] - ct);
    }
    invntt_tomont(w);
    for c in w.iter_mut() {
        *c = caddq(*c);
    }
    use_hint_poly(w, hints, row);
    pack_w1(w1_out, w);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use fips204::ml_dsa_44;
    use fips204::traits::{SerDes, Signer};
    use std::vec::Vec;

    fn verify(pk: &[u8], sig: &[u8], msg: &[u8]) -> bool {
        if pk.len() != PK_BYTES || sig.len() != SIG_BYTES {
            return false;
        }
        if !hints_valid(sig_hints(sig)) {
            return false;
        }
        let mut rho = [0u8; SEED_BYTES];
        rho.copy_from_slice(pk_rho(pk));
        let mut a_hat: Vec<i32> = std::vec![0i32; K * L * N];
        for r in 0..K {
            for s in 0..L {
                expand_a_poly(poly_mut(&mut a_hat, r * L + s), &rho, r as u8, s as u8);
            }
        }
        let mu = message_mu(&pk_tr(pk), msg);
        let mut c_hat = [0i32; N];
        prepare_c(&mut c_hat, sig);
        let mut z_hat: Vec<i32> = std::vec![0i32; L * N];
        for i in 0..L {
            if !prepare_z(poly_mut(&mut z_hat, i), sig, i) {
                return false;
            }
        }
        let mut t1_hat: Vec<i32> = std::vec![0i32; K * N];
        for i in 0..K {
            prepare_t1(poly_mut(&mut t1_hat, i), pk, i);
        }
        let mut w1_enc = [0u8; K * POLYW1_PACKED];
        let mut w = [0i32; N];
        for row in 0..K {
            let a_row = &a_hat[row * L * N..(row + 1) * L * N];
            let w1_row = &mut w1_enc[row * POLYW1_PACKED..(row + 1) * POLYW1_PACKED];
            compute_row(&mut w, a_row, &z_hat, &c_hat, poly(&t1_hat, row), sig_hints(sig), row, w1_row);
        }
        final_challenge(&mu, &w1_enc) == sig_ctilde(sig)
    }

    #[test]
    fn accepts_fips204_signatures() {
        for _ in 0..8 {
            let (pk, sk) = ml_dsa_44::try_keygen().unwrap();
            let msg = [0x42u8; 32];
            let sig = sk.try_sign(&msg, &[]).unwrap();
            assert!(verify(&pk.into_bytes(), &sig, &msg));
        }
    }

    #[test]
    fn rejects_tampered_signature_and_message() {
        let (pk, sk) = ml_dsa_44::try_keygen().unwrap();
        let pk = pk.into_bytes();
        let msg = [0x42u8; 32];
        let sig = sk.try_sign(&msg, &[]).unwrap();
        let mut bad = sig;
        bad[CTILDE_BYTES + 100] ^= 1;
        assert!(!verify(&pk, &bad, &msg));
        let mut bad = sig;
        bad[5] ^= 1;
        assert!(!verify(&pk, &bad, &msg));
        let mut other = msg;
        other[0] ^= 1;
        assert!(!verify(&pk, &sig, &other));
        let (pk2, _) = ml_dsa_44::try_keygen().unwrap();
        assert!(!verify(&pk2.into_bytes(), &sig, &msg));
    }

    #[test]
    fn ntt_roundtrip() {
        let mut a = [0i32; N];
        for (i, c) in a.iter_mut().enumerate() {
            *c = (i as i32 * 7919) % Q;
        }
        let orig = a;
        ntt(&mut a);
        invntt_tomont(&mut a);
        for i in 0..N {
            let back = montgomery_reduce(a[i] as i64);
            let back = caddq(reduce32(back));
            assert_eq!(back, orig[i], "coeff {}", i);
        }
    }
}
