use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::ID as INSTRUCTIONS_ID;

use crate::errors::VaultError;
use crate::quorum::{
    approval_digest, set_pq_mode_params_hash, verify_pq_approval, verify_quorum,
    ACTION_SET_PQ_MODE,
};
use crate::state::{Coordinator, PQ_MODE_MLDSA, PQ_MODE_OFF};

#[derive(Accounts)]
pub struct SetPqMode<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"coordinator", coordinator.issuer_authority.as_ref()],
        bump = coordinator.bump
    )]
    pub coordinator: Account<'info, Coordinator>,
    /// CHECK: validated by address against the instructions sysvar id
    #[account(address = INSTRUCTIONS_ID)]
    pub instructions_sysvar: AccountInfo<'info>,
    /// CHECK: owner, discriminator and contents are validated in verify_pq_approval according to the coordinator's pq_mode
    pub pq_state: Option<UncheckedAccount<'info>>,
}

pub fn set_pq_mode_handler(
    ctx: Context<SetPqMode>,
    mode: u8,
    pk_commit: [u8; 32],
    expiry_slot: u64,
) -> Result<()> {
    require!(mode <= PQ_MODE_MLDSA, VaultError::InvalidPqMode);
    require!(
        mode == PQ_MODE_OFF || pk_commit != [0u8; 32],
        VaultError::InvalidPqMode
    );
    require!(
        Clock::get()?.slot <= expiry_slot,
        VaultError::ApprovalExpired
    );

    let coordinator = &ctx.accounts.coordinator;
    let params_hash = set_pq_mode_params_hash(mode, &pk_commit);
    let digest = approval_digest(
        ACTION_SET_PQ_MODE,
        ctx.program_id,
        &coordinator.key(),
        coordinator.nonce,
        expiry_slot,
        &params_hash,
    );
    verify_quorum(&ctx.accounts.instructions_sysvar, coordinator, &digest)?;
    let pq_info = ctx.accounts.pq_state.as_ref().map(|a| a.to_account_info());
    verify_pq_approval(coordinator, pq_info.as_ref(), &digest)?;

    let coordinator = &mut ctx.accounts.coordinator;
    coordinator.pq_mode = mode;
    coordinator.pq_pk_commit = pk_commit;
    coordinator.nonce = coordinator
        .nonce
        .checked_add(1)
        .ok_or(VaultError::Overflow)?;
    Ok(())
}
