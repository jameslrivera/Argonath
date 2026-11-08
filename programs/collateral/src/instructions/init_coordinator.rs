use anchor_lang::prelude::*;

use crate::errors::VaultError;
use crate::state::{Coordinator, MAX_ADMINS};

#[derive(Accounts)]
pub struct InitCoordinator<'info> {
    #[account(mut)]
    pub issuer_authority: Signer<'info>,
    #[account(
        init,
        payer = issuer_authority,
        space = 8 + Coordinator::INIT_SPACE,
        seeds = [b"coordinator", issuer_authority.key().as_ref()],
        bump
    )]
    pub coordinator: Account<'info, Coordinator>,
    pub system_program: Program<'info, System>,
}

pub fn init_coordinator_handler(
    ctx: Context<InitCoordinator>,
    admins: Vec<Pubkey>,
    threshold: u8,
) -> Result<()> {
    require!(admins.len() <= MAX_ADMINS, VaultError::TooManyAdmins);
    require!(
        threshold >= 1 && (threshold as usize) <= admins.len(),
        VaultError::InvalidThreshold
    );
    for (i, admin) in admins.iter().enumerate() {
        require!(!admins[..i].contains(admin), VaultError::DuplicateAdmin);
    }

    let coordinator = &mut ctx.accounts.coordinator;
    coordinator.issuer_authority = ctx.accounts.issuer_authority.key();
    coordinator.admins = admins;
    coordinator.threshold = threshold;
    coordinator.nonce = 0;
    coordinator.paused = false;
    coordinator.bump = ctx.bumps.coordinator;
    Ok(())
}
