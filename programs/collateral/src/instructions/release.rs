use anchor_lang::prelude::*;

use crate::errors::VaultError;
use crate::state::{AuthHold, Collateral, Coordinator};

#[derive(Accounts)]
pub struct Release<'info> {
    pub caller: Signer<'info>,
    #[account(
        seeds = [b"coordinator", coordinator.issuer_authority.as_ref()],
        bump = coordinator.bump,
        has_one = issuer_authority
    )]
    pub coordinator: Account<'info, Coordinator>,
    #[account(mut)]
    pub issuer_authority: SystemAccount<'info>,
    #[account(
        mut,
        seeds = [
            b"collateral",
            collateral.coordinator.as_ref(),
            collateral.owner.as_ref(),
            collateral.mint.as_ref()
        ],
        bump = collateral.bump,
        has_one = coordinator
    )]
    pub collateral: Account<'info, Collateral>,
    #[account(
        mut,
        close = issuer_authority,
        seeds = [
            b"hold",
            collateral.key().as_ref(),
            auth_hold.id.to_le_bytes().as_ref()
        ],
        bump = auth_hold.bump,
        has_one = collateral
    )]
    pub auth_hold: Account<'info, AuthHold>,
}

pub fn release_handler(ctx: Context<Release>) -> Result<()> {
    let is_issuer = ctx.accounts.caller.key() == ctx.accounts.issuer_authority.key();
    if !is_issuer {
        require!(
            Clock::get()?.slot > ctx.accounts.auth_hold.expiry_slot,
            VaultError::HoldNotExpired
        );
    }

    let amount = ctx.accounts.auth_hold.amount;
    let collateral = &mut ctx.accounts.collateral;
    collateral.held = collateral
        .held
        .checked_sub(amount)
        .ok_or(VaultError::Overflow)?;
    Ok(())
}
