use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::ID as INSTRUCTIONS_ID;

use crate::errors::VaultError;
use crate::quorum::{
    approval_digest, rotate_admins_params_hash, verify_pq_approval, verify_quorum,
    ACTION_ROTATE_ADMINS,
};
use crate::state::{Coordinator, MAX_ADMINS};

#[derive(Accounts)]
pub struct RotateAdmins<'info> {
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

pub fn rotate_admins_handler(
    ctx: Context<RotateAdmins>,
    new_admins: Vec<Pubkey>,
    new_threshold: u8,
    expiry_slot: u64,
) -> Result<()> {
    require!(new_admins.len() <= MAX_ADMINS, VaultError::TooManyAdmins);
    require!(
        new_threshold >= 1 && (new_threshold as usize) <= new_admins.len(),
        VaultError::InvalidThreshold
    );
    for (i, admin) in new_admins.iter().enumerate() {
        require!(!new_admins[..i].contains(admin), VaultError::DuplicateAdmin);
    }
    require!(
        Clock::get()?.slot <= expiry_slot,
        VaultError::ApprovalExpired
    );

    let coordinator = &ctx.accounts.coordinator;
    let params_hash = rotate_admins_params_hash(&new_admins, new_threshold);
    let digest = approval_digest(
        ACTION_ROTATE_ADMINS,
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
    coordinator.admins = new_admins;
    coordinator.threshold = new_threshold;
    coordinator.nonce = coordinator
        .nonce
        .checked_add(1)
        .ok_or(VaultError::Overflow)?;
    Ok(())
}
