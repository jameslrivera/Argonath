use anchor_lang::prelude::*;

use crate::errors::VaultError;
use crate::state::{Coordinator, PqVerifyState, PQ_MODE_HYBRID, PQ_MODE_OFF};

pub fn verify_pq_approval(
    coordinator: &Coordinator,
    pq_state: Option<&Account<PqVerifyState>>,
    expected_digest: &[u8; 32],
) -> Result<()> {
    match coordinator.pq_mode {
        PQ_MODE_OFF => Ok(()),
        PQ_MODE_HYBRID => {
            let state = pq_state.ok_or_else(|| error!(VaultError::PqApprovalRequired))?;
            require!(state.done, VaultError::PqIncomplete);
            require!(
                state.digest == *expected_digest,
                VaultError::PqDigestMismatch
            );
            require!(
                state.pk_commit == coordinator.pq_pk_commit,
                VaultError::PqKeyMismatch
            );
            Ok(())
        }
        _ => Err(error!(VaultError::InvalidPqMode)),
    }
}
