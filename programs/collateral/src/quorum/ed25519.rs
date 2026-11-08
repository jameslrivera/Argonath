use anchor_lang::prelude::*;
use anchor_lang::solana_program::ed25519_program;
use anchor_lang::solana_program::sysvar::instructions::{
    load_current_index_checked, load_instruction_at_checked,
};

use crate::errors::VaultError;
use crate::state::Coordinator;

const SIGNATURE_SERIALIZED_SIZE: usize = 64;
const PUBKEY_SERIALIZED_SIZE: usize = 32;
const OFFSETS_HEADER_SIZE: usize = 2;
const OFFSETS_ENTRY_SIZE: usize = 14;
const SELF_REFERENCE: u16 = u16::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumError {
    TooFewEntries,
    Malformed,
    NonSelfReference,
    MessageMismatch,
    NotAnAdmin,
    DuplicateSignature,
    QuorumNotMet,
}

impl From<QuorumError> for VaultError {
    fn from(e: QuorumError) -> Self {
        match e {
            QuorumError::TooFewEntries | QuorumError::QuorumNotMet => VaultError::QuorumNotMet,
            QuorumError::Malformed | QuorumError::NonSelfReference => {
                VaultError::InvalidSignatureEntry
            }
            QuorumError::MessageMismatch => VaultError::MessageMismatch,
            QuorumError::NotAnAdmin => VaultError::NotAnAdmin,
            QuorumError::DuplicateSignature => VaultError::DuplicateSignature,
        }
    }
}

struct Ed25519Offsets {
    signature_offset: u16,
    signature_ix_index: u16,
    public_key_offset: u16,
    public_key_ix_index: u16,
    message_offset: u16,
    message_size: u16,
    message_ix_index: u16,
}

fn read_u16_le(data: &[u8], at: usize) -> core::result::Result<u16, QuorumError> {
    let slice = data.get(at..at + 2).ok_or(QuorumError::Malformed)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_offsets(data: &[u8], index: usize) -> core::result::Result<Ed25519Offsets, QuorumError> {
    let base = OFFSETS_HEADER_SIZE + index * OFFSETS_ENTRY_SIZE;
    Ok(Ed25519Offsets {
        signature_offset: read_u16_le(data, base)?,
        signature_ix_index: read_u16_le(data, base + 2)?,
        public_key_offset: read_u16_le(data, base + 4)?,
        public_key_ix_index: read_u16_le(data, base + 6)?,
        message_offset: read_u16_le(data, base + 8)?,
        message_size: read_u16_le(data, base + 10)?,
        message_ix_index: read_u16_le(data, base + 12)?,
    })
}

fn slice_at(data: &[u8], offset: u16, len: usize) -> core::result::Result<&[u8], QuorumError> {
    let start = offset as usize;
    let end = start.checked_add(len).ok_or(QuorumError::Malformed)?;
    data.get(start..end).ok_or(QuorumError::Malformed)
}

pub fn scan_quorum(
    data: &[u8],
    admins: &[Pubkey],
    expected_digest: &[u8; 32],
    threshold: usize,
    enforce_self_ref: bool,
) -> core::result::Result<(), QuorumError> {
    let n = *data.first().ok_or(QuorumError::Malformed)? as usize;
    if n < threshold {
        return Err(QuorumError::TooFewEntries);
    }

    let mut seen: Vec<Pubkey> = Vec::with_capacity(n);
    for i in 0..n {
        let offs = read_offsets(data, i)?;

        if enforce_self_ref
            && (offs.signature_ix_index != SELF_REFERENCE
                || offs.public_key_ix_index != SELF_REFERENCE
                || offs.message_ix_index != SELF_REFERENCE)
        {
            return Err(QuorumError::NonSelfReference);
        }

        let _ = slice_at(data, offs.signature_offset, SIGNATURE_SERIALIZED_SIZE)?;
        let pk_bytes = slice_at(data, offs.public_key_offset, PUBKEY_SERIALIZED_SIZE)?;
        let msg = slice_at(data, offs.message_offset, offs.message_size as usize)?;

        if msg != expected_digest.as_ref() {
            return Err(QuorumError::MessageMismatch);
        }

        let pk = Pubkey::try_from(pk_bytes).map_err(|_| QuorumError::Malformed)?;
        if !admins.contains(&pk) {
            return Err(QuorumError::NotAnAdmin);
        }
        if seen.contains(&pk) {
            return Err(QuorumError::DuplicateSignature);
        }
        seen.push(pk);
    }

    if seen.len() < threshold {
        return Err(QuorumError::QuorumNotMet);
    }
    Ok(())
}

pub fn verify_quorum(
    instructions_sysvar: &AccountInfo,
    coordinator: &Coordinator,
    expected_digest: &[u8; 32],
) -> Result<()> {
    let current_index = load_current_index_checked(instructions_sysvar)? as usize;
    require!(current_index >= 1, VaultError::MissingEd25519Instruction);
    let ed_ix = load_instruction_at_checked(current_index - 1, instructions_sysvar)?;
    require_keys_eq!(
        ed_ix.program_id,
        ed25519_program::ID,
        VaultError::MissingEd25519Instruction
    );

    let enforce_self_ref = !cfg!(feature = "vulnerable");
    scan_quorum(
        ed_ix.data.as_slice(),
        &coordinator.admins,
        expected_digest,
        coordinator.threshold as usize,
        enforce_self_ref,
    )
    .map_err(|e| error!(VaultError::from(e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admins(n: usize) -> Vec<Pubkey> {
        (0..n).map(|_| Pubkey::new_unique()).collect()
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        let set = admins(3);
        let digest = [7u8; 32];
        let mut state: u64 = 0x9E3779B97F4A7C15;
        for len in 0..260usize {
            for _ in 0..40 {
                let mut data = vec![0u8; len];
                for b in data.iter_mut() {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *b = (state & 0xff) as u8;
                }
                let _ = scan_quorum(&data, &set, &digest, 2, true);
                let _ = scan_quorum(&data, &set, &digest, 2, false);
            }
        }
    }
}
