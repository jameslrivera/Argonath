use anchor_lang::prelude::*;
use anchor_spl::token_interface::{
    transfer_checked, Mint, TokenAccount, TokenInterface, TransferChecked,
};

use crate::errors::VaultError;
use crate::state::Collateral;

#[derive(Accounts)]
pub struct WithdrawFree<'info> {
    pub owner: Signer<'info>,
    #[account(
        mut,
        seeds = [
            b"collateral",
            collateral.coordinator.as_ref(),
            collateral.owner.as_ref(),
            collateral.mint.as_ref()
        ],
        bump = collateral.bump,
        has_one = owner,
        has_one = mint
    )]
    pub collateral: Account<'info, Collateral>,
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
        token::authority = owner,
        token::token_program = token_program
    )]
    pub owner_token_account: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

pub fn withdraw_free_handler(ctx: Context<WithdrawFree>, amount: u64) -> Result<()> {
    require!(amount > 0, VaultError::ZeroAmount);
    let collateral = &ctx.accounts.collateral;
    require!(amount <= collateral.free(), VaultError::InsufficientFree);

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
                to: ctx.accounts.owner_token_account.to_account_info(),
                authority: ctx.accounts.collateral.to_account_info(),
            },
            &[seeds],
        ),
        amount,
        ctx.accounts.mint.decimals,
    )?;

    let collateral = &mut ctx.accounts.collateral;
    collateral.deposited = collateral
        .deposited
        .checked_sub(amount)
        .ok_or(VaultError::Overflow)?;
    Ok(())
}
