use anchor_lang::prelude::*;

pub mod errors;
pub mod instructions;
pub mod quorum;
pub mod state;

use instructions::*;

declare_id!("41DLEct3Mu2ggxAKWbLNKVQimALYuNMFz8saTpKewVTa");

#[program]
pub mod collateral {
    use super::*;

    pub fn init_coordinator(
        ctx: Context<InitCoordinator>,
        admins: Vec<Pubkey>,
        threshold: u8,
    ) -> Result<()> {
        instructions::init_coordinator::init_coordinator_handler(ctx, admins, threshold)
    }

    pub fn open_collateral(ctx: Context<OpenCollateral>) -> Result<()> {
        instructions::open_collateral::open_collateral_handler(ctx)
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        instructions::deposit::deposit_handler(ctx, amount)
    }

    pub fn withdraw_free(ctx: Context<WithdrawFree>, amount: u64) -> Result<()> {
        instructions::withdraw_free::withdraw_free_handler(ctx, amount)
    }

    pub fn authorize(
        ctx: Context<Authorize>,
        amount: u64,
        expiry_slot: u64,
        merchant_ref: [u8; 32],
    ) -> Result<()> {
        instructions::authorize::authorize_handler(ctx, amount, expiry_slot, merchant_ref)
    }

    pub fn settle(ctx: Context<Settle>, amount: u64) -> Result<()> {
        instructions::settle::settle_handler(ctx, amount)
    }

    pub fn release(ctx: Context<Release>) -> Result<()> {
        instructions::release::release_handler(ctx)
    }

    pub fn set_paused(ctx: Context<SetPaused>, paused: bool) -> Result<()> {
        instructions::set_paused::set_paused_handler(ctx, paused)
    }

    pub fn admin_withdraw(
        ctx: Context<AdminWithdraw>,
        amount: u64,
        expiry_slot: u64,
    ) -> Result<()> {
        instructions::admin_withdraw::admin_withdraw_handler(ctx, amount, expiry_slot)
    }

    pub fn rotate_admins(
        ctx: Context<RotateAdmins>,
        new_admins: Vec<Pubkey>,
        new_threshold: u8,
        expiry_slot: u64,
    ) -> Result<()> {
        instructions::rotate_admins::rotate_admins_handler(
            ctx,
            new_admins,
            new_threshold,
            expiry_slot,
        )
    }

    pub fn pq_open(ctx: Context<PqOpen>, digest: [u8; 32], pk_commit: [u8; 32]) -> Result<()> {
        instructions::pq_verify::pq_open_handler(ctx, digest, pk_commit)
    }

    pub fn pq_verify_chunk(
        ctx: Context<PqVerifyChunk>,
        start: u8,
        sigs: Vec<[u8; 32]>,
    ) -> Result<()> {
        instructions::pq_verify::pq_verify_chunk_handler(ctx, start, sigs)
    }

    pub fn pq_finalize(ctx: Context<PqFinalize>) -> Result<()> {
        instructions::pq_verify::pq_finalize_handler(ctx)
    }

    pub fn set_pq_mode(
        ctx: Context<SetPqMode>,
        mode: u8,
        pk_commit: [u8; 32],
        expiry_slot: u64,
    ) -> Result<()> {
        instructions::set_pq_mode::set_pq_mode_handler(ctx, mode, pk_commit, expiry_slot)
    }

    pub fn migrate_coordinator(ctx: Context<MigrateCoordinator>) -> Result<()> {
        instructions::migrate_coordinator::migrate_coordinator_handler(ctx)
    }
}
