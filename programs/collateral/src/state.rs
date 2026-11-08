use anchor_lang::prelude::*;

pub const MAX_ADMINS: usize = 8;

pub const PQ_MODE_OFF: u8 = 0;
pub const PQ_MODE_HYBRID: u8 = 1;
pub const PQ_MODE_MLDSA: u8 = 2;

#[account] 
#[derive(InitSpace)]
pub struct Coordinator {
    pub issuer_authority: Pubkey,
    #[max_len(MAX_ADMINS)]
    pub admins: Vec<Pubkey>,
    pub threshold:u8,
    pub nonce: u64,
    pub paused: bool,
    pub bump: u8,
    pub pq_mode: u8,
    pub pq_pk_commit: [u8; 32],
}

#[account]
#[derive(InitSpace)]
pub struct Collateral {
    pub coordinator: Pubkey,
    pub owner: Pubkey,
    pub mint: Pubkey,
    pub deposited: u64,
    pub held: u64,
    pub settled: u64,
    pub hold_count: u64,
    pub bump: u8,

}

#[account]
#[derive(InitSpace)]
pub struct AuthHold {
    pub collateral: Pubkey,
    pub id: u64,
    pub amount: u64,
    pub expiry_slot: u64,
    pub merchant_ref: [u8; 32],
    pub bump: u8,
}

impl Collateral {
    pub fn free(&self) -> u64 {
        self.deposited.saturating_sub(self.held)
    }
}

pub const PQ_LEN: usize = 67;
pub const PQ_TIPS_BYTES: usize = 32 * PQ_LEN;

#[account]
#[derive(InitSpace)]
pub struct PqVerifyState {
    pub authority: Pubkey,
    pub digest: [u8; 32],
    pub pk_commit: [u8; 32],
    pub tips: [u8; PQ_TIPS_BYTES],
    pub filled_bitmap: u128,
    pub done: bool,
    pub bump: u8,
}

impl PqVerifyState {
    pub fn all_filled(&self) -> bool {
        self.filled_bitmap == (1u128 << PQ_LEN) - 1
    }
}

pub const MLDSA_BLOB_BYTES: usize = mldsa_verify::PK_BYTES + mldsa_verify::SIG_BYTES;
pub const MLDSA_STAGE_LOADING: u8 = 0;
pub const MLDSA_STAGE_EXPANDING: u8 = 1;
pub const MLDSA_STAGE_HASH: u8 = 2;
pub const MLDSA_STAGE_POLYS: u8 = 3;
pub const MLDSA_STAGE_ROWS: u8 = 4;
pub const MLDSA_STAGE_FINALIZE: u8 = 5;
pub const MLDSA_STAGE_DONE: u8 = 6;

#[account(zero_copy)]
pub struct MlDsaVerifyState {
    pub a_hat: [i32; 4096],
    pub z_hat: [i32; 1024],
    pub t1_hat: [i32; 1024],
    pub c_hat: [i32; 256],
    pub authority: Pubkey,
    pub digest: [u8; 32],
    pub mu: [u8; 64],
    pub pk_hash: [u8; 32],
    pub w1_enc: [u8; 768],
    pub blob: [u8; 3732],
    pub loaded: u32,
    pub a_done: u8,
    pub stage: u8,
    pub rows_done: u8,
    pub done: u8,
}

impl MlDsaVerifyState {
    pub const SPACE: usize = 8 + core::mem::size_of::<MlDsaVerifyState>();

    pub fn pk(&self) -> &[u8] {
        &self.blob[..mldsa_verify::PK_BYTES]
    }
    pub fn sig(&self) -> &[u8] {
        &self.blob[mldsa_verify::PK_BYTES..]
    }
}
