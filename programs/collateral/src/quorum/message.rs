use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hashv;

pub const QUORUM_DOMAIN: &[u8] = b"PQVAULT_QUORUM_V1";

pub const ACTION_ADMIN_WITHDRAW: u8 = 1;
pub const ACTION_ROTATE_ADMINS: u8 = 2;
pub const ACTION_SET_PQ_MODE: u8 = 3;

pub fn approval_digest(
    action_tag: u8,
    program_id: &Pubkey,
    coordinator: &Pubkey,
    nonce: u64,
    expiry_slot: u64,
    params_hash: &[u8; 32],
) -> [u8; 32] {
    hashv(&[
        QUORUM_DOMAIN,
        &[action_tag],
        program_id.as_ref(),
        coordinator.as_ref(),
        &nonce.to_le_bytes(),
        &expiry_slot.to_le_bytes(),
        params_hash,
    ])
    .to_bytes()
}

pub fn admin_withdraw_params_hash(
    collateral: &Pubkey,
    destination: &Pubkey,
    amount: u64,
) -> [u8; 32] {
    hashv(&[
        collateral.as_ref(),
        destination.as_ref(),
        &amount.to_le_bytes(),
    ])
    .to_bytes()
}

pub fn rotate_admins_params_hash(admins: &[Pubkey], threshold: u8) -> [u8; 32] {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(admins.len() + 1);
    for a in admins {
        parts.push(a.as_ref());
    }
    let threshold_bytes = [threshold];
    parts.push(&threshold_bytes);
    hashv(&parts).to_bytes()
}

pub fn set_pq_mode_params_hash(mode: u8, pk_commit: &[u8; 32]) -> [u8; 32] {
    hashv(&[&[mode], pk_commit]).to_bytes()
}
