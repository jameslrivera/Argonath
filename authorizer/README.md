# Authorizer service

A reference issuer backend for Argonath. It drives the
card lifecycle against the on-chain program and emits webhooks, standing in for
the auth/settlement loop a card network would run.

## Run

```
npm install
RPC_URL=http://127.0.0.1:8899 \
IDL_PATH=../target/idl/collateral.json \
ISSUER_KEYPAIR=~/.config/solana/id.json \
WEBHOOK_URL=http://localhost:9099/ \
npm start
```

## Endpoints

| Method | Path | Body | Effect |
| --- | --- | --- | --- |
| GET | `/health` | — | program id + coordinator |
| GET | `/vault/:owner/:mint` | — | deposited / held / free / settled |
| POST | `/authorize` | `owner, mint, amount, expirySlots?, merchantRef?` | place a hold, emit `authorization.created` |
| POST | `/settle` | `owner, mint, holdId, amount` | settle a hold, emit `settlement.completed` |
| POST | `/release` | `owner, mint, holdId` | release a hold, emit `hold.released` |

## Admin approval signer

`sign-approval` builds the off-chain M-of-N approval an admin set signs for a
quorum-gated action. The transaction signer never needs an admin key.

```
node dist/sign-approval.js admin-withdraw \
  --program <PROGRAM_ID> --coordinator <PDA> \
  --collateral <PDA> --destination <ATA> \
  --amount <u64> --nonce <n> --expiry <slot> \
  --admin key1.json --admin key2.json
```

It prints the approval digest and a base64 Ed25519 precompile instruction to
place immediately before the program instruction.

`set-pq-mode` enrols (or rotates) the admin set's post-quantum key and
switches the coordinator between Ed25519-only (`--mode 0`), WOTS hybrid
(`--mode 1`, `--pk-commit` is the WOTS commitment) and ML-DSA-44 hybrid
(`--mode 2`, `--pk-commit` is the SHA-256 of the ML-DSA public key):

```
node dist/sign-approval.js set-pq-mode \
  --program <PROGRAM_ID> --coordinator <PDA> \
  --mode 1 --pk-commit <32-byte hex> \
  --nonce <n> --expiry <slot> \
  --admin key1.json --admin key2.json
```

In hybrid mode the transaction must also pass a finalized verification state
over the same digest as the `pq_state` account (`pqState: null` otherwise):
a `PqVerifyState` in mode 1, an `MlDsaVerifyState` in mode 2. `src/mldsa.ts`
streams an ML-DSA-44 verification for a digest and returns that account.
