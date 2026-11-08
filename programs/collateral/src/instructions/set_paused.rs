use anchor_lang::prelude::*;

use crate::state::Coordinator;

#[derive(Accounts)]
pub struct SetPaused<'info> {
    pub issuer_authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"coordinator", coordinator.issuer_authority.as_ref()],
        bump = coordinator.bump,
        has_one = issuer_authority
    )]
    pub coordinator: Account<'info, Coordinator>,
}

pub fn set_paused_handler(ctx: Context<SetPaused>, paused: bool) -> Result<()> {
    ctx.accounts.coordinator.paused = paused;
    Ok(())
}
