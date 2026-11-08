use anchor_lang::prelude::*;

use crate::errors::VaultError;
use crate::state::{AuthHold, Collateral, Coordinator};

#[derive(Accounts)]
pub struct Authorize<'info> {
    #[account(mut)]
    pub issuer_authority: Signer<'info>,
    #[account(
        seeds = [b"coordinator", coordinator.issuer_authority.as_ref()],
        bump = coordinator.bump,
        has_one = issuer_authority
    )]
    pub coordinator: Account<'info, Coordinator>,
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
        init,
        payer = issuer_authority,
        space = 8 + AuthHold::INIT_SPACE,
        seeds = [
            b"hold",
            collateral.key().as_ref(),
            collateral.hold_count.to_le_bytes().as_ref()
        ],
        bump
    )]
    pub auth_hold: Account<'info, AuthHold>,
    pub system_program: Program<'info, System>,
}

pub fn authorize_handler(
    ctx: Context<Authorize>,
    amount: u64,
    expiry_slot: u64,
    merchant_ref: [u8; 32],
) -> Result<()> {
    require!(!ctx.accounts.coordinator.paused, VaultError::Paused);
    require!(amount > 0, VaultError::ZeroAmount);
    require!(expiry_slot > Clock::get()?.slot, VaultError::BadExpiry);

    let collateral = &mut ctx.accounts.collateral;
    require!(amount <= collateral.free(), VaultError::InsufficientFree);

    let hold = &mut ctx.accounts.auth_hold;
    hold.collateral = collateral.key();
    hold.id = collateral.hold_count;
    hold.amount = amount;
    hold.expiry_slot = expiry_slot;
    hold.merchant_ref = merchant_ref;
    hold.bump = ctx.bumps.auth_hold;

    collateral.held = collateral
        .held
        .checked_add(amount)
        .ok_or(VaultError::Overflow)?;
    collateral.hold_count = collateral
        .hold_count
        .checked_add(1)
        .ok_or(VaultError::Overflow)?;
    Ok(())
}
