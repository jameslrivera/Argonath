use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::state::{Collateral, Coordinator};

#[derive(Accounts)]
pub struct OpenCollateral<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    pub coordinator: Account<'info, Coordinator>,
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(
        init,
        payer = owner,
        space = 8 + Collateral::INIT_SPACE,
        seeds = [
            b"collateral",
            coordinator.key().as_ref(),
            owner.key().as_ref(),
            mint.key().as_ref()
        ],
        bump
    )]
    pub collateral: Account<'info, Collateral>,
    #[account(
        init,
        payer = owner,
        associated_token::mint = mint,
        associated_token::authority = collateral,
        associated_token::token_program = token_program
    )]
    pub vault_token_account: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

pub fn open_collateral_handler(ctx: Context<OpenCollateral>) -> Result<()> {
    let collateral = &mut ctx.accounts.collateral;
    collateral.coordinator = ctx.accounts.coordinator.key();
    collateral.owner = ctx.accounts.owner.key();
    collateral.mint = ctx.accounts.mint.key();
    collateral.deposited = 0;
    collateral.held = 0;
    collateral.settled = 0;
    collateral.hold_count = 0;
    collateral.bump = ctx.bumps.collateral;
    Ok(())
}
