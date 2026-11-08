use anchor_lang::prelude::*;
use anchor_lang::Discriminator;

use crate::errors::VaultError;
use crate::state::{
    Coordinator, MlDsaVerifyState, PqVerifyState, MLDSA_STAGE_DONE, PQ_MODE_HYBRID, PQ_MODE_MLDSA,
    PQ_MODE_OFF,
};

const WOTS_DIGEST_OFFSET: usize = 8 + 32;
const WOTS_PK_COMMIT_OFFSET: usize = WOTS_DIGEST_OFFSET + 32;
const WOTS_DONE_OFFSET: usize = WOTS_PK_COMMIT_OFFSET + 32 + 32 * 67 + 16;

pub fn verify_pq_approval(
    coordinator: &Coordinator,
    pq_state: Option<&AccountInfo>,
    expected_digest: &[u8; 32],
) -> Result<()> {
    match coordinator.pq_mode {
        PQ_MODE_OFF => Ok(()),
        PQ_MODE_HYBRID => {
            let info = pq_state.ok_or_else(|| error!(VaultError::PqApprovalRequired))?;
            require_keys_eq!(*info.owner, crate::ID, ErrorCode::AccountOwnedByWrongProgram);
            let data = info.try_borrow_data()?;
            require!(
                data.len() > WOTS_DONE_OFFSET && &data[..8] == PqVerifyState::DISCRIMINATOR,
                ErrorCode::AccountDiscriminatorMismatch
            );
            require!(data[WOTS_DONE_OFFSET] == 1, VaultError::PqIncomplete);
            require!(
                &data[WOTS_DIGEST_OFFSET..WOTS_DIGEST_OFFSET + 32] == expected_digest,
                VaultError::PqDigestMismatch
            );
            require!(
                data[WOTS_PK_COMMIT_OFFSET..WOTS_PK_COMMIT_OFFSET + 32] == coordinator.pq_pk_commit,
                VaultError::PqKeyMismatch
            );
            Ok(())
        }
        PQ_MODE_MLDSA => {
            let info = pq_state.ok_or_else(|| error!(VaultError::PqApprovalRequired))?;
            require_keys_eq!(*info.owner, crate::ID, ErrorCode::AccountOwnedByWrongProgram);
            let data = info.try_borrow_data()?;
            require!(
                data.len() == MlDsaVerifyState::SPACE
                    && &data[..8] == MlDsaVerifyState::DISCRIMINATOR,
                ErrorCode::AccountDiscriminatorMismatch
            );
            let state: &MlDsaVerifyState = bytemuck::try_from_bytes(&data[8..])
                .map_err(|_| error!(ErrorCode::AccountDidNotDeserialize))?;
            require!(
                state.done == 1 && state.stage == MLDSA_STAGE_DONE,
                VaultError::PqIncomplete
            );
            require!(state.digest == *expected_digest, VaultError::PqDigestMismatch);
            require!(
                state.pk_hash == coordinator.pq_pk_commit,
                VaultError::PqKeyMismatch
            );
            Ok(())
        }
        _ => Err(error!(VaultError::InvalidPqMode)),
    }
}
