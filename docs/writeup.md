# Argonath: quantum-hardening a stablecoin card vault on Solana

## The problem

A stablecoin card locks the cardholder's collateral in an on-chain vault the
issuer can draw against. Cardholders move their own funds; the issuer places
holds and settles charges; and a small admin set can force a withdrawal in
exceptional cases. That admin path is the highest-value target in the system:
one accepted forgery moves everyone's collateral.

Admin signatures on Solana fail in two ways, one present and one scheduled.

**The check can be wrong.** Programs verify Ed25519 signatures through a
precompile instruction. Each entry carries offset fields that say *where* to
find the signature, public key, and message: inside the precompile instruction
itself (index `u16::MAX`) or inside a different instruction. A program that
reads each public key out of the precompile data and trusts it, without
checking that the entry points at itself, can be handed one genuine signature
from a throwaway key plus entries carrying real admin public keys with garbage
signatures whose offsets point back at the genuine entry. The precompile
follows the pointers, re-verifies the one real signature, and passes; the
program counts the admins as signers (CWE-347, trust of unverified data). On
August 28, 2026 this exact omission let an attacker holding none of the admin
keys drain about $1.1M from card vaults built on Rain.

**The key can be wrong.** Every key on Solana is Ed25519, which a
cryptographically relevant quantum computer breaks. A vault that will hold
collateral for years has a dated liability: its admin quorum must move to a
quantum-resistant scheme without a flag day, and without trusting the new
verifier more than the old one.

This write-up builds the vault, gets the Ed25519 quorum right, then adds a
hash-based post-quantum quorum and gates admin actions on both.

## Part 1: the vault

An Anchor program with one deployment per partner (`Coordinator`) and one vault
per cardholder (`Collateral`). Cardholders keep withdrawal authority over their
own funds; the issuer can place authorization holds and settle card charges
against them.

- `deposit` / `withdraw_free`: the cardholder controls free collateral.
- `authorize` / `settle` / `release`: the issuer places a hold, captures part
  or all of it, or releases it; holds auto-expire.
- `set_paused`: the issuer can pause its own actions. It never blocks a
  cardholder's `withdraw_free`, which preserves self-custody.

## Part 2: the Ed25519 admin quorum, done right

Forced withdrawals (`admin_withdraw`) and admin-set changes (`rotate_admins`)
require an M-of-N quorum of off-chain admin signatures, verified on-chain
through the Ed25519 precompile. The single missing line from the Rain incident
is present here: every signature entry's three instruction-index fields must
equal `u16::MAX`.

```
if enforce_self_ref
    && (offs.signature_ix_index != SELF_REFERENCE
        || offs.public_key_ix_index != SELF_REFERENCE
        || offs.message_ix_index != SELF_REFERENCE)
{
    return Err(QuorumError::NonSelfReference);
}
```

The approval message binds the program id, coordinator, a per-coordinator
nonce, an expiry slot, an action tag, and the action's parameters. The nonce
stops replay; the action tag stops an approval for one action being reused for
another. The transaction fee-payer needs no admin key: authority comes entirely
from the detached signatures.

The same program compiles two ways. With the `vulnerable` feature, the
self-reference check is removed, reproducing Rain's bug. `tests/exploit.ts`
shows an attacker with no admin keys draining the vault against that build;
`tests/quorum.ts` shows the identical transaction rejected with
`InvalidSignatureEntry` against the default build.

The parser was factored into a runtime-free `scan_quorum`, fuzzed against
arbitrary bytes (`fuzz/`, plus a host test of ~10,000 inputs) to confirm it
never panics and never accepts a non-self-referential entry.

## Part 3: a post-quantum admin quorum

Every key on Solana today is Ed25519, which a cryptographically relevant
quantum computer would break. The admin quorum is the highest-value target: one
forged quorum moves collateral. So the quorum is the place to add a
quantum-resistant signature.

### What ships: hash-based (WOTS)

A classic Winternitz one-time signature over SHA-256 (w=16) is quantum-resistant
and uses only hashing, which Solana has as a cheap syscall. The catch is size: a
signature is 67 chains x 32 bytes = 2144 bytes, larger than the 1232-byte
transaction limit. So verification streams: `pq_verify_chunk` processes a slice
of the chains into a `PqVerifyState` PDA across several transactions, then
`pq_finalize` hashes the recovered chain tips and checks them against the stored
public-key commitment.

Measured on a local validator (`bench/results.csv`):

| Metric | Value |
| --- | --- |
| Signature | 2144 bytes, 67 chains |
| Transactions | 6 (5 chunks + finalize) |
| Max chunk | ~25,000 to 28,000 CU |
| Total verify | ~110,000 to 125,000 CU |

Every transaction lands far under the 1.4M CU limit. The binding constraint is
transaction size, not compute, which is exactly why it streams. XMSS (a Merkle
tree over WOTS leaves) turns the one-time key into a many-time key by adding an
authentication path; the verifier for that path is implemented and tested in
`crates/pq-verify`.

### What also ships: ML-DSA-44 (FIPS 204), streamed and off the stack

ML-DSA is NIST's primary post-quantum signature and the one most systems will
adopt, so the vault has to verify it too. The obstacle is specific. Both
published Rust verifiers compile to Solana's SBF target and both overflow its
4096-byte stack frame:

| Scheme | Verify stack frame | Over the 4096-byte limit |
| --- | --- | --- |
| ML-DSA-44 (`fips204`) | 8448 bytes | +4296 |
| Falcon-512 (`fn-dsa-vrfy`) | 6272 bytes | +64 (decode: +128) |

`cargo-build-sbf` emits the frame-size error and warns the result "may cause
undefined behavior during execution." The compute budget was never the
problem; the working set was. Reproduce with `bench/lattice/probe.sh`.

Argonath's answer is a verifier written for the constraint. `crates/mldsa-verify`
is a `no_std` implementation of FIPS 204 Algorithm 8 (ML-DSA.Verify) for the
44 parameter set whose every function takes its buffers by reference, so
nothing larger than a SHAKE state lives on the stack. On-chain, all working
state lives in a 30 KB zero-copy account: the public key and signature, the
16 expanded matrix polynomials in NTT form, the transformed `z`, `t1` and `c`,
and the packed `w1`. Verification is a state machine, one bounded piece per
transaction:

| Step | What runs | Transactions | CU each |
| --- | --- | --- | --- |
| open | create and tag the state account | 1 | ~2,000 |
| load | stream pk and sig in 900-byte chunks | 5 | ~1,200 |
| expand | 8 of 16 matrix polys, SHAKE128 rejection sampling | 2 | ~594,000 |
| prepare_hash | tr = SHAKE256(pk), mu = SHAKE256(tr, 0, 0, M) | 1 | ~153,000 |
| prepare_polys | SampleInBall, decode z and t1, 9 NTTs, z norm check | 1 | ~499,000 |
| row | w' = INTT(A*z - c*t1*2^d), UseHint, w1Encode, 4 rows | 1 | ~449,000 |
| finalize | SHAKE256(mu, w1) == c~ | 1 | ~94,000 |
| total | | 12 | ~2,390,000 |

The expensive step is SHAKE: Keccak has no syscall on Solana, so the 16 matrix
polynomials cost about 74,000 CU each in software. Everything else is integer
arithmetic the SBF VM handles well.

Correctness rests on three independent implementations agreeing. The crate's
host tests verify signatures produced by the `fips204` crate. The on-chain
tests verify signatures produced by noble's `ml_dsa44`. Tampering with one
signature byte, one key byte, or the message is rejected at finalize.

### Hybrid design

The production posture is hybrid: an action requires both the Ed25519 quorum
and a finalized post-quantum approval over the same bound message, so a bug in
the newer path cannot weaken the Ed25519 guarantee, and a future quantum break
cannot bypass the hash-based one.

The coordinator carries a `pq_mode` flag and a `pq_pk_commit`. Mode 1 enrols
the SHA-256 commitment to a WOTS public key; mode 2 enrols the SHA-256 of an
ML-DSA-44 public key. `set_pq_mode` enrols the key and switches modes; like
every admin action it is gated by the Ed25519 quorum over an approval digest
(`ACTION_SET_PQ_MODE`, nonce, expiry, mode, commitment).

In hybrid mode every quorum-gated instruction (`admin_withdraw`,
`rotate_admins`, and `set_pq_mode` itself) takes an optional `pq_state`
account and requires that it is a finalized verification state owned by the
program of the type the mode calls for (`PqVerifyState` or `MlDsaVerifyState`),
that its `digest` equals the approval digest the Ed25519 signers signed, and
that its key commitment equals the coordinator's enrolled key. The
approval digest already binds the action, program, coordinator, nonce, expiry
and parameters, so a finalized PQ state is usable for exactly one action and
dies with the nonce. Because leaving hybrid mode is itself a hybrid-gated
action, a compromised Ed25519 quorum cannot downgrade the coordinator back to
Ed25519-only.

`migrate_coordinator` resizes a pre-hybrid coordinator account in place
(zero-filled, so it starts in Ed25519-only mode) and tops up its rent, which is
the upgrade path for a coordinator that is already live.

WOTS is a one-time scheme: after a PQ approval is consumed, the admin set
rotates to a fresh commitment with `set_pq_mode`, approved under the key being
retired. Replacing the single commitment with an XMSS root (the many-time
verifier is already in `crates/pq-verify`) removes that rotation step and is
the next change on this path.

## Status

- 51 on-chain tests and 9 host unit tests pass.
- The forgery is proven to drain the vulnerable build and to be rejected by the
  secure build.
- ML-DSA-44 (FIPS 204) signatures are verified fully on-chain in 12
  transactions, about 2.4M CU in total, with all polynomial state in a 30 KB
  zero-copy account.
- A hash-based WOTS signature is verified on-chain in 6 transactions at
  roughly 110,000 to 125,000 CU.
- The hybrid gate is wired for both families: in hybrid mode an Ed25519 quorum
  alone is rejected with `PqApprovalRequired`, and the same action succeeds
  once a finalized post-quantum approval over the same digest is attached.
- The program is deployed on devnet as
  `41DLEct3Mu2ggxAKWbLNKVQimALYuNMFz8saTpKewVTa`, with its IDL published
  on-chain, and both hybrid modes have been exercised there end to end.
