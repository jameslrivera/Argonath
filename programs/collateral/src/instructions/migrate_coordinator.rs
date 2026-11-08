use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};
use anchor_lang::Discriminator;

use crate::errors::VaultError;
use crate::state::Coordinator;

#[derive(Accounts)]
pub struct MigrateCoordinator<'info> {
    #[account(mut)]
    pub issuer_authority: Signer<'info>,
    /// CHECK: PDA bound to the signer by seeds; owner and discriminator are checked by hand because a pre-hybrid account is shorter than `Coordinator`
    #[account(
        mut,
        seeds = [b"coordinator", issuer_authority.key().as_ref()],
        bump
    )]
    pub coordinator: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

pub fn migrate_coordinator_handler(ctx: Context<MigrateCoordinator>) -> Result<()> {
    let account = ctx.accounts.coordinator.to_account_info();
    require_keys_eq!(
        *account.owner,
        *ctx.program_id,
        ErrorCode::AccountOwnedByWrongProgram
    );
    let target_len = 8 + Coordinator::INIT_SPACE;
    {
        let data = account.try_borrow_data()?;
        require!(
            data.len() >= 8 && &data[..8] == Coordinator::DISCRIMINATOR,
            ErrorCode::AccountDiscriminatorMismatch
        );
        require!(
            data.len() < target_len,
            VaultError::CoordinatorAlreadyMigrated
        );
    }

    let needed = Rent::get()?.minimum_balance(target_len);
    let have = account.lamports();
    if needed > have {
        transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.issuer_authority.to_account_info(),
                    to: account.clone(),
                },
            ),
            needed - have,
        )?;
    }
    account.resize(target_len)?;
    Ok(())
}
