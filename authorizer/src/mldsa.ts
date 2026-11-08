import { Program } from "@coral-xyz/anchor";
import {
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SystemProgram,
} from "@solana/web3.js";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa";

export const MLDSA_STATE_SPACE =
  8 + 4096 * 4 + 1024 * 4 + 1024 * 4 + 256 * 4 + 32 + 32 + 64 + 32 + 768 + 3732 + 4 + 4;
export const PK_BYTES = 1312;
export const SIG_BYTES = 2420;
const LOAD_CHUNK = 900;
const EXPAND_PER_TX = 8;
const ROWS_PER_TX = 4;

export function mldsaKeypair(seed: Uint8Array) {
  const kp = ml_dsa44.keygen(seed);
  return { pk: Buffer.from(kp.publicKey), sk: kp.secretKey };
}

export function mldsaSign(sk: Uint8Array, digest: Buffer): Buffer {
  return Buffer.from(ml_dsa44.sign(sk, digest));
}

const budget = () => [
  ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
  ComputeBudgetProgram.requestHeapFrame({ bytes: 64 * 1024 }),
];

export async function mldsaStream(
  program: Program,
  authority: Keypair,
  digest: Buffer,
  pk: Buffer,
  sig: Buffer,
  onTx: (label: string, sig: string) => Promise<void> | void
): Promise<PublicKey> {
  const conn = program.provider.connection;
  const state = Keypair.generate();
  const lamports = await conn.getMinimumBalanceForRentExemption(MLDSA_STATE_SPACE);
  const create = SystemProgram.createAccount({
    fromPubkey: authority.publicKey,
    newAccountPubkey: state.publicKey,
    lamports,
    space: MLDSA_STATE_SPACE,
    programId: program.programId,
  });
  const acct = { authority: authority.publicKey, state: state.publicKey };
  await onTx(
    "Create verification state (30 KB)",
    await program.methods
      .mlDsaOpen(Array.from(digest))
      .accounts(acct)
      .preInstructions([create])
      .signers([authority, state])
      .rpc()
  );
  const blob = Buffer.concat([pk, sig]);
  for (let off = 0; off < blob.length; off += LOAD_CHUNK) {
    const chunk = blob.subarray(off, Math.min(off + LOAD_CHUNK, blob.length));
    await onTx(
      `Load public key and signature, bytes ${off}–${off + chunk.length}`,
      await program.methods.mlDsaLoad(off, chunk).accounts(acct).signers([authority]).rpc()
    );
  }
  for (let done = 0; done < 16; done += EXPAND_PER_TX) {
    await onTx(
      `Expand matrix A, polynomials ${done}–${done + EXPAND_PER_TX - 1}`,
      await program.methods
        .mlDsaExpand(EXPAND_PER_TX)
        .accounts(acct)
        .preInstructions(budget())
        .signers([authority])
        .rpc()
    );
  }
  await onTx(
    "Compute message hash (tr, mu)",
    await program.methods.mlDsaPrepareHash().accounts(acct).preInstructions(budget()).signers([authority]).rpc()
  );
  await onTx(
    "Decode and transform c, z, t1",
    await program.methods.mlDsaPreparePolys().accounts(acct).preInstructions(budget()).signers([authority]).rpc()
  );
  for (let row = 0; row < 4; row += ROWS_PER_TX) {
    await onTx(
      "Compute w' = A·z − c·t1, apply hints",
      await program.methods.mlDsaRow(ROWS_PER_TX).accounts(acct).preInstructions(budget()).signers([authority]).rpc()
    );
  }
  await onTx(
    "Finalize: challenge matches, signature accepted",
    await program.methods.mlDsaFinalize().accounts(acct).preInstructions(budget()).signers([authority]).rpc()
  );
  return state.publicKey;
}
