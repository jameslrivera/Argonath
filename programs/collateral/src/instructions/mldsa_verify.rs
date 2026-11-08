use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hashv;
use mldsa_verify as ml;

use crate::errors::VaultError;
use crate::state::{
    MlDsaVerifyState, MLDSA_BLOB_BYTES, MLDSA_STAGE_DONE, MLDSA_STAGE_EXPANDING,
    MLDSA_STAGE_FINALIZE, MLDSA_STAGE_HASH, MLDSA_STAGE_LOADING, MLDSA_STAGE_POLYS,
    MLDSA_STAGE_ROWS,
};

#[derive(Accounts)]
pub struct MlDsaOpen<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(zero)]
    pub state: AccountLoader<'info, MlDsaVerifyState>,
}

pub fn ml_dsa_open_handler(ctx: Context<MlDsaOpen>, digest: [u8; 32]) -> Result<()> {
    let mut st = ctx.accounts.state.load_init()?;
    st.authority = ctx.accounts.authority.key();
    st.digest = digest;
    st.stage = MLDSA_STAGE_LOADING;
    Ok(())
}

#[derive(Accounts)]
pub struct MlDsaStep<'info> {
    pub authority: Signer<'info>,
    #[account(mut, has_one = authority)]
    pub state: AccountLoader<'info, MlDsaVerifyState>,
}

pub fn ml_dsa_load_handler(ctx: Context<MlDsaStep>, offset: u32, data: Vec<u8>) -> Result<()> {
    let mut st = ctx.accounts.state.load_mut()?;
    require!(st.stage == MLDSA_STAGE_LOADING, VaultError::MlDsaBadStage);
    let off = offset as usize;
    require!(
        off == st.loaded as usize && off + data.len() <= MLDSA_BLOB_BYTES && !data.is_empty(),
        VaultError::MlDsaBadOffset
    );
    st.blob[off..off + data.len()].copy_from_slice(&data);
    st.loaded += data.len() as u32;
    if st.loaded as usize == MLDSA_BLOB_BYTES {
        require!(ml::hints_valid(ml::sig_hints(st.sig())), VaultError::MlDsaMalformed);
        st.stage = MLDSA_STAGE_EXPANDING;
    }
    Ok(())
}

pub fn ml_dsa_expand_handler(ctx: Context<MlDsaStep>, count: u8) -> Result<()> {
    let mut st = ctx.accounts.state.load_mut()?;
    require!(st.stage == MLDSA_STAGE_EXPANDING, VaultError::MlDsaBadStage);
    let mut rho = [0u8; ml::SEED_BYTES];
    rho.copy_from_slice(ml::pk_rho(st.pk()));
    let st = &mut *st;
    for _ in 0..count {
        let idx = st.a_done as usize;
        if idx >= ml::K * ml::L {
            break;
        }
        let (r, s) = ((idx / ml::L) as u8, (idx % ml::L) as u8);
        ml::expand_a_poly(ml::poly_mut(&mut st.a_hat, idx), &rho, r, s);
        st.a_done += 1;
    }
    if st.a_done as usize == ml::K * ml::L {
        st.stage = MLDSA_STAGE_HASH;
    }
    Ok(())
}

pub fn ml_dsa_prepare_hash_handler(ctx: Context<MlDsaStep>) -> Result<()> {
    let mut st = ctx.accounts.state.load_mut()?;
    require!(st.stage == MLDSA_STAGE_HASH, VaultError::MlDsaBadStage);
    let st = &mut *st;
    st.pk_hash = hashv(&[st.pk()]).to_bytes();
    let tr = ml::pk_tr(st.pk());
    st.mu = ml::message_mu(&tr, &st.digest);
    st.stage = MLDSA_STAGE_POLYS;
    Ok(())
}

pub fn ml_dsa_prepare_polys_handler(ctx: Context<MlDsaStep>) -> Result<()> {
    let mut st = ctx.accounts.state.load_mut()?;
    require!(st.stage == MLDSA_STAGE_POLYS, VaultError::MlDsaBadStage);
    let MlDsaVerifyState {
        blob,
        z_hat,
        t1_hat,
        c_hat,
        stage,
        ..
    } = &mut *st;
    let pk = &blob[..ml::PK_BYTES];
    let sig = &blob[ml::PK_BYTES..];
    ml::prepare_c(c_hat, sig);
    for i in 0..ml::L {
        require!(
            ml::prepare_z(ml::poly_mut(z_hat, i), sig, i),
            VaultError::MlDsaMalformed
        );
    }
    for i in 0..ml::K {
        ml::prepare_t1(ml::poly_mut(t1_hat, i), pk, i);
    }
    *stage = MLDSA_STAGE_ROWS;
    Ok(())
}

pub fn ml_dsa_row_handler(ctx: Context<MlDsaStep>, count: u8) -> Result<()> {
    let mut st = ctx.accounts.state.load_mut()?;
    require!(st.stage == MLDSA_STAGE_ROWS, VaultError::MlDsaBadStage);
    let MlDsaVerifyState {
        a_hat,
        z_hat,
        t1_hat,
        c_hat,
        w1_enc,
        blob,
        rows_done,
        stage,
        ..
    } = &mut *st;
    let sig = &blob[ml::PK_BYTES..];
    let mut w: Box<ml::Poly> = Box::new([0i32; ml::N]);
    for _ in 0..count {
        let row = *rows_done as usize;
        if row >= ml::K {
            break;
        }
        ml::compute_row(
            &mut w,
            &a_hat[row * ml::L * ml::N..(row + 1) * ml::L * ml::N],
            &z_hat[..],
            c_hat,
            ml::poly(&t1_hat[..], row),
            ml::sig_hints(sig),
            row,
            &mut w1_enc[row * ml::POLYW1_PACKED..(row + 1) * ml::POLYW1_PACKED],
        );
        *rows_done += 1;
    }
    if *rows_done as usize == ml::K {
        *stage = MLDSA_STAGE_FINALIZE;
    }
    Ok(())
}

pub fn ml_dsa_finalize_handler(ctx: Context<MlDsaStep>) -> Result<()> {
    let mut st = ctx.accounts.state.load_mut()?;
    require!(st.stage == MLDSA_STAGE_FINALIZE, VaultError::MlDsaBadStage);
    let expected = ml::final_challenge(&st.mu, &st.w1_enc);
    require!(
        expected[..] == *ml::sig_ctilde(st.sig()),
        VaultError::MlDsaVerifyFailed
    );
    st.done = 1;
    st.stage = MLDSA_STAGE_DONE;
    Ok(())
}
