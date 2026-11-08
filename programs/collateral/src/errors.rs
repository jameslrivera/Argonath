use anchor_lang::prelude::*;

#[error_code]
pub enum VaultError {
    #[msg("Coordinator is paused")]
    Paused,
    #[msg("Threshold must be between 1 and the number of admins")]
    InvalidThreshold,
    #[msg("Too many admins")]
    TooManyAdmins,
    #[msg("Duplicate admin key")]
    DuplicateAdmin,
    #[msg("Amount must be greater than zero")]
    ZeroAmount,
    #[msg("Insufficient free collateral")]
    InsufficientFree,
    #[msg("Settlement exceeds hold amount")]
    SettleExceedsHold,
    #[msg("Hold has not expired")]
    HoldNotExpired,
    #[msg("Hold has expired")]
    HoldExpired,
    #[msg("Expiry slot must be in the future")]
    BadExpiry,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Unauthorized signer")]
    Unauthorized,
    #[msg("Expected Ed25519 precompile instruction not found")]
    MissingEd25519Instruction,
    #[msg("Ed25519 signature entry does not reference itself")]
    InvalidSignatureEntry,
    #[msg("Signer is not a registered admin")]
    NotAnAdmin,
    #[msg("Duplicate admin signature")]
    DuplicateSignature,
    #[msg("Not enough admin signatures")]
    QuorumNotMet,
    #[msg("Approval message does not match this action")]
    MessageMismatch,
    #[msg("Approval nonce does not match")]
    BadNonce,
    #[msg("Approval has expired")]
    ApprovalExpired,
    #[msg("Post-quantum verification already finalized")]
    PqAlreadyDone,
    #[msg("Chain index out of range")]
    PqIndexOutOfRange,
    #[msg("Not all chains have been verified")]
    PqIncomplete,
    #[msg("Recovered public key does not match commitment")]
    PqCommitmentMismatch,
    #[msg("Empty chunk")]
    PqEmptyChunk,
    #[msg("Hybrid mode requires a finalized post-quantum approval")]
    PqApprovalRequired,
    #[msg("Post-quantum approval does not match this action")]
    PqDigestMismatch,
    #[msg("Post-quantum approval was not made under the coordinator's PQ key")]
    PqKeyMismatch,
    #[msg("Unknown post-quantum mode or empty key commitment")]
    InvalidPqMode,
    #[msg("Coordinator already uses the current layout")]
    CoordinatorAlreadyMigrated,
    #[msg("ML-DSA verification state is not at the expected stage")]
    MlDsaBadStage,
    #[msg("ML-DSA bytes must be loaded sequentially within bounds")]
    MlDsaBadOffset,
    #[msg("ML-DSA public key or signature is malformed")]
    MlDsaMalformed,
    #[msg("ML-DSA signature verification failed")]
    MlDsaVerifyFailed,
}
