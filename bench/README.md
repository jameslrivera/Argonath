# Compute-unit benchmarks

Both files are generated against a local validator by the test suite:
`results.csv` by `tests/pq.ts` (WOTS) and `mldsa-results.csv` by
`tests/mldsa.ts` (ML-DSA-44). They measure the on-chain cost of verifying one
post-quantum signature for the admin quorum.

## ML-DSA-44 (FIPS 204, Dilithium)

The reference Rust verifiers overflow Solana's 4096-byte stack frame (see the
lattice probes below), so Argonath verifies ML-DSA-44 with all working state in
a 30 KB zero-copy account and streams the computation across transactions.

| Step | Transactions | CU each |
| --- | --- | --- |
| open | 1 | ~2,000 |
| load pk and sig (900-byte chunks) | 5 | ~1,200 |
| expand matrix A (8 polys each) | 2 | ~594,000 |
| prepare hashes (tr, mu) | 1 | ~153,000 |
| prepare polys (c, z, t1 to NTT) | 1 | ~499,000 |
| rows (A*z - c*t1, UseHint, pack) | 1 | ~449,000 |
| finalize | 1 | ~94,000 |
| **total** | **12** | **~2,390,000** |

Keccak has no syscall on Solana, so SHAKE128 matrix expansion dominates at
about 74,000 CU per polynomial.

## WOTS (hash-based, SHA-256, w=16)

A single WOTS signature is 67 chains x 32 bytes = 2144 bytes, which exceeds
Solana's 1232-byte transaction limit, so it streams across `pq_verify_chunk`
transactions into a `PqVerifyState` PDA and `pq_finalize` checks the recovered
tips against the stored public-key commitment.

| Metric | Value |
| --- | --- |
| Chains | 67 |
| Signature size | 2144 bytes |
| Transactions | 6 (5 chunks + finalize) |
| Max chunk CU | ~25,000 to 28,000 |
| Total verify CU | ~110,000 to 125,000 |

## Lattice probes

`lattice/probe.sh` compiles the published `fips204` (ML-DSA-44) and
`fn-dsa-vrfy` (Falcon-512) verifiers for the SBF target and shows the
stack-frame overflow that motivated the streamed design above.

| Scheme | Verify stack frame | Over the limit |
| --- | --- | --- |
| ML-DSA-44 (`fips204`) | 8448 bytes | +4296 |
| Falcon-512 (`fn-dsa-vrfy`) | 6272 bytes | +64 (decode +128) |
