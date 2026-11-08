use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::ID as INSTRUCTIONS_ID;
use anchor_spl::token_interface::{
    transfer_checked, Mint, TokenAccount, TokenInterface, TransferChecked,
};

use crate::errors::VaultError;
use crate::quorum::{
    admin_withdraw_params_hash, approval_digest, verify_pq_approval, verify_quorum,
    ACTION_ADMIN_WITHDRAW,
};
use crate::state::{Collateral, Coordinator};

#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"coordinator", coordinator.issuer_authority.as_ref()],
        bump = coordinator.bump
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
        token::token_program = token_program
    )]
    pub destination_token_account: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
    /// CHECK: validated by address against the instructions sysvar id
    #[account(address = INSTRUCTIONS_ID)]
    pub instructions_sysvar: AccountInfo<'info>,
    /// CHECK: owner, discriminator and contents are validated in verify_pq_approval according to the coordinator's pq_mode
    pub pq_state: Option<UncheckedAccount<'info>>,
}

pub fn admin_withdraw_handler(
    ctx: Context<AdminWithdraw>,
    amount: u64,
    expiry_slot: u64,
) -> Result<()> {
    require!(amount > 0, VaultError::ZeroAmount);
    require!(
        Clock::get()?.slot <= expiry_slot,
        VaultError::ApprovalExpired
    );

    let coordinator = &ctx.accounts.coordinator;
    let destination = ctx.accounts.destination_token_account.key();
    let params_hash =
        admin_withdraw_params_hash(&ctx.accounts.collateral.key(), &destination, amount);
    let digest = approval_digest(
        ACTION_ADMIN_WITHDRAW,
        ctx.program_id,
        &coordinator.key(),
        coordinator.nonce,
        expiry_slot,
        &params_hash,
    );
    verify_quorum(&ctx.accounts.instructions_sysvar, coordinator, &digest)?;
    let pq_info = ctx.accounts.pq_state.as_ref().map(|a| a.to_account_info());
    verify_pq_approval(coordinator, pq_info.as_ref(), &digest)?;

    require!(
        amount <= ctx.accounts.collateral.deposited,
        VaultError::InsufficientFree
    );

    let collateral = &ctx.accounts.collateral;
    let coord_key = collateral.coordinator;
    let owner = collateral.owner;
    let mint = collateral.mint;
    let bump = collateral.bump;
    let seeds: &[&[u8]] = &[
        b"collateral",
        coord_key.as_ref(),
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
                to: ctx.accounts.destination_token_account.to_account_info(),
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
    if collateral.held > collateral.deposited {
        collateral.held = collateral.deposited;
    }

    let coordinator = &mut ctx.accounts.coordinator;
    coordinator.nonce = coordinator
        .nonce
        .checked_add(1)
        .ok_or(VaultError::Overflow)?;
    Ok(())
}
