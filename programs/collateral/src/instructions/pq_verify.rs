use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hashv;

use crate::errors::VaultError;
use crate::state::{PqVerifyState, PQ_LEN};

struct SyscallHasher;
impl pq_verify::Hasher for SyscallHasher {
    fn hash(&self, parts: &[&[u8]]) -> [u8; 32] {
        hashv(parts).to_bytes()
    }
}

#[derive(Accounts)]
#[instruction(digest: [u8; 32])]
pub struct PqOpen<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        init,
        payer = authority,
        space = 8 + PqVerifyState::INIT_SPACE,
        seeds = [b"pq", authority.key().as_ref(), digest.as_ref()],
        bump
    )]
    pub state: Box<Account<'info, PqVerifyState>>,
    pub system_program: Program<'info, System>,
}

pub fn pq_open_handler(ctx: Context<PqOpen>, digest: [u8; 32], pk_commit: [u8; 32]) -> Result<()> {
    let state = &mut ctx.accounts.state;
    state.authority = ctx.accounts.authority.key();
    state.digest = digest;
    state.pk_commit = pk_commit;
    state.filled_bitmap = 0;
    state.done = false;
    state.bump = ctx.bumps.state;
    Ok(())
}

#[derive(Accounts)]
pub struct PqVerifyChunk<'info> {
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"pq", state.authority.as_ref(), state.digest.as_ref()],
        bump = state.bump,
        has_one = authority
    )]
    pub state: Box<Account<'info, PqVerifyState>>,
}

pub fn pq_verify_chunk_handler(
    ctx: Context<PqVerifyChunk>,
    start: u8,
    sigs: Vec<[u8; 32]>,
) -> Result<()> {
    let state = &mut ctx.accounts.state;
    require!(!state.done, VaultError::PqAlreadyDone);
    require!(!sigs.is_empty(), VaultError::PqEmptyChunk);

    let digits = pq_verify::message_digits(&state.digest);
    let hasher = SyscallHasher;

    for (offset, sig) in sigs.iter().enumerate() {
        let idx = start as usize + offset;
        require!(idx < PQ_LEN, VaultError::PqIndexOutOfRange);
        let steps = (pq_verify::W - 1) - digits[idx] as usize;
        let tip = pq_verify::chain(&hasher, sig, steps);
        state.tips[idx * 32..idx * 32 + 32].copy_from_slice(&tip);
        state.filled_bitmap |= 1u128 << idx;
    }
    Ok(())
}

#[derive(Accounts)]
pub struct PqFinalize<'info> {
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"pq", state.authority.as_ref(), state.digest.as_ref()],
        bump = state.bump,
        has_one = authority
    )]
    pub state: Box<Account<'info, PqVerifyState>>,
}

pub fn pq_finalize_handler(ctx: Context<PqFinalize>) -> Result<()> {
    let state = &mut ctx.accounts.state;
    require!(!state.done, VaultError::PqAlreadyDone);
    require!(state.all_filled(), VaultError::PqIncomplete);

    let recovered = hashv(&[&state.tips]).to_bytes();
    require!(
        recovered == state.pk_commit,
        VaultError::PqCommitmentMismatch
    );
    state.done = true;
    Ok(())
}
