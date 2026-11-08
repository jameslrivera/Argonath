use anchor_lang::prelude::*;
use anchor_spl::token_interface::{
    transfer_checked, Mint, TokenAccount, TokenInterface, TransferChecked,
};

use crate::errors::VaultError;
use crate::state::{AuthHold, Collateral, Coordinator};

#[derive(Accounts)]
pub struct Settle<'info> {
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
        has_one = coordinator,
        has_one = mint
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
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = collateral,
        associated_token::token_program = token_program
    )]
    pub vault_token_account: InterfaceAccount<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = mint,
        token::authority = issuer_authority,
        token::token_program = token_program
    )]
    pub issuer_token_account: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

pub fn settle_handler(ctx: Context<Settle>, amount: u64) -> Result<()> {
    require!(!ctx.accounts.coordinator.paused, VaultError::Paused);
    require!(amount > 0, VaultError::ZeroAmount);

    let hold = &ctx.accounts.auth_hold;
    require!(
        Clock::get()?.slot <= hold.expiry_slot,
        VaultError::HoldExpired
    );
    require!(amount <= hold.amount, VaultError::SettleExceedsHold);
    let hold_amount = hold.amount;

    let collateral = &ctx.accounts.collateral;
    let coordinator = collateral.coordinator;
    let owner = collateral.owner;
    let mint = collateral.mint;
    let bump = collateral.bump;
    let seeds: &[&[u8]] = &[
        b"collateral",
        coordinator.as_ref(),
        owner.as_ref(),
        mint.as_ref(),
        &[bump],
    ];

    transfer_checked(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.vault_token_account.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.issuer_token_account.to_account_info(),
                authority: ctx.accounts.collateral.to_account_info(),
            },
            &[seeds],
        ),
        amount,
        ctx.accounts.mint.decimals,
    )?;

    let collateral = &mut ctx.accounts.collateral;
    collateral.held = collateral
        .held
        .checked_sub(hold_amount)
        .ok_or(VaultError::Overflow)?;
    collateral.deposited = collateral
        .deposited
        .checked_sub(amount)
        .ok_or(VaultError::Overflow)?;
    collateral.settled = collateral
        .settled
        .checked_add(amount)
        .ok_or(VaultError::Overflow)?;
    Ok(())
}
