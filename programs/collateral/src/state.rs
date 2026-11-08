use anchor_lang::prelude::*;

pub const MAX_ADMINS: usize = 8;

#[account]
#[derive(InitSpace)]
pub struct Coordinator {
    pub issuer_authority: Pubkey,
    #[max_len(MAX_ADMINS)]
    pub admins: Vec<Pubkey>,
    pub threshold: u8,
    pub nonce: u64,
    pub paused: bool,
    pub bump: u8,
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
