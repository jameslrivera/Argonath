import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SystemProgram,
} from "@solana/web3.js";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa";
import { expect } from "chai";
import { createHash } from "crypto";
import fs from "fs";
import path from "path";
import { Collateral } from "../target/types/collateral";

export const MLDSA_STATE_SPACE =
  8 + 4096 * 4 + 1024 * 4 + 1024 * 4 + 256 * 4 + 32 + 32 + 64 + 32 + 768 + 3732 + 4 + 4;
export const LOAD_CHUNK = 900;
export const EXPAND_PER_TX = Number(process.env.MLDSA_EXPAND_PER_TX ?? 8);
export const ROWS_PER_TX = Number(process.env.MLDSA_ROWS_PER_TX ?? 4);
export const PK_BYTES = 1312;
export const SIG_BYTES = 2420;

export function mldsaKeypair(seedByte: number) {
  const seed = new Uint8Array(32).fill(seedByte);
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

export interface StreamResult {
  state: PublicKey;
  sigs: { label: string; sig: string }[];
}

export async function mldsaStream(
  program: Program<Collateral>,
  authority: Keypair,
  digest: Buffer,
  pk: Buffer,
  sig: Buffer,
  opts: { stopBeforeFinalize?: boolean } = {}
): Promise<StreamResult> {
  const conn = program.provider.connection;
  const state = Keypair.generate();
  const sigs: { label: string; sig: string }[] = [];
  const lamports = await conn.getMinimumBalanceForRentExemption(MLDSA_STATE_SPACE);
  const create = SystemProgram.createAccount({
    fromPubkey: authority.publicKey,
    newAccountPubkey: state.publicKey,
    lamports,
    space: MLDSA_STATE_SPACE,
    programId: program.programId,
  });
  sigs.push({
    label: "open",
    sig: await program.methods
      .mlDsaOpen(Array.from(digest))
      .accounts({ authority: authority.publicKey, state: state.publicKey })
      .preInstructions([create])
      .signers([authority, state])
      .rpc(),
  });
  const blob = Buffer.concat([pk, sig]);
  for (let off = 0; off < blob.length; off += LOAD_CHUNK) {
    const chunk = blob.subarray(off, Math.min(off + LOAD_CHUNK, blob.length));
    sigs.push({
      label: `load@${off}`,
      sig: await program.methods
        .mlDsaLoad(off, chunk)
        .accounts({ authority: authority.publicKey, state: state.publicKey })
        .signers([authority])
        .rpc(),
    });
  }
  for (let done = 0; done < 16; done += EXPAND_PER_TX) {
    sigs.push({
      label: `expand@${done}`,
      sig: await program.methods
        .mlDsaExpand(EXPAND_PER_TX)
        .accounts({ authority: authority.publicKey, state: state.publicKey })
        .preInstructions(budget())
        .signers([authority])
        .rpc(),
    });
  }
  sigs.push({
    label: "prepare_hash",
    sig: await program.methods
      .mlDsaPrepareHash()
      .accounts({ authority: authority.publicKey, state: state.publicKey })
      .preInstructions(budget())
      .signers([authority])
      .rpc(),
  });
  sigs.push({
    label: "prepare_polys",
    sig: await program.methods
      .mlDsaPreparePolys()
      .accounts({ authority: authority.publicKey, state: state.publicKey })
      .preInstructions(budget())
      .signers([authority])
      .rpc(),
  });
  for (let row = 0; row < 4; row += ROWS_PER_TX) {
    sigs.push({
      label: `rows@${row}`,
      sig: await program.methods
        .mlDsaRow(ROWS_PER_TX)
        .accounts({ authority: authority.publicKey, state: state.publicKey })
        .preInstructions(budget())
        .signers([authority])
        .rpc(),
    });
  }
  if (!opts.stopBeforeFinalize) {
    sigs.push({
      label: "finalize",
      sig: await program.methods
        .mlDsaFinalize()
        .accounts({ authority: authority.publicKey, state: state.publicKey })
        .preInstructions(budget())
        .signers([authority])
        .rpc(),
    });
  }
  return { state: state.publicKey, sigs };
}

export async function cuOf(conn: anchor.web3.Connection, sig: string): Promise<number> {
  for (let attempt = 0; attempt < 20; attempt++) {
    const tx = await conn.getTransaction(sig, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    const cu = tx?.meta?.computeUnitsConsumed;
    if (cu !== undefined && cu !== null) return cu;
    await new Promise((r) => setTimeout(r, 300));
  }
  return 0;
}

describe("post-quantum ML-DSA-44 (FIPS 204) streaming verifier", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Collateral as Program<Collateral>;
  const authority = (provider.wallet as anchor.Wallet).payer;

  it("verifies a valid ML-DSA-44 signature across transactions and records CU", async () => {
    const { pk, sk } = mldsaKeypair(3);
    const digest = createHash("sha256").update("ML-DSA on Solana " + Date.now()).digest();
    const sig = mldsaSign(sk, digest);
    expect(ml_dsa44.verify(pk, digest, sig)).to.eq(true);

    const { state, sigs } = await mldsaStream(program, authority, digest, pk, sig);
    const acc = await program.account.mlDsaVerifyState.fetch(state);
    expect(acc.done).to.eq(1);
    expect(Buffer.from(acc.digest).equals(digest)).to.eq(true);

    const rows: string[] = ["scheme,metric,value"];
    let total = 0;
    let max = 0;
    for (const s of sigs) {
      const cu = await cuOf(provider.connection, s.sig);
      total += cu;
      max = Math.max(max, cu);
      rows.push(`ML-DSA-44,${s.label}_cu,${cu}`);
    }
    rows.push(`ML-DSA-44,transactions,${sigs.length}`);
    rows.push(`ML-DSA-44,max_tx_cu,${max}`);
    rows.push(`ML-DSA-44,total_verify_cu,${total}`);
    rows.push(`ML-DSA-44,pk_bytes,${PK_BYTES}`);
    rows.push(`ML-DSA-44,sig_bytes,${SIG_BYTES}`);
    rows.push(`ML-DSA-44,state_bytes,${MLDSA_STATE_SPACE}`);
    const outDir = path.resolve(__dirname, "../bench");
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(path.join(outDir, "mldsa-results.csv"), rows.join("\n") + "\n");
    console.log(
      `    ML-DSA-44 verify: ${sigs.length} txs, max tx ${max} CU, total ${total} CU`
    );
    expect(max).to.be.lessThan(1_400_000);
  });

  it("rejects a tampered ML-DSA-44 signature at finalize", async () => {
    const { pk, sk } = mldsaKeypair(4);
    const digest = createHash("sha256").update("tamper " + Date.now()).digest();
    const sig = mldsaSign(sk, digest);
    const bad = Buffer.from(sig);
    bad[40] ^= 0x01;
    let failed = false;
    try {
      await mldsaStream(program, authority, digest, pk, bad);
    } catch (e: any) {
      failed = String(e).includes("MlDsaVerifyFailed");
      if (!failed) throw e;
    }
    expect(failed).to.eq(true);
  });

  it("rejects a signature over a different message", async () => {
    const { pk, sk } = mldsaKeypair(5);
    const digest = createHash("sha256").update("real " + Date.now()).digest();
    const other = createHash("sha256").update("other " + Date.now()).digest();
    const sig = mldsaSign(sk, other);
    let failed = false;
    try {
      await mldsaStream(program, authority, digest, pk, sig);
    } catch (e: any) {
      failed = String(e).includes("MlDsaVerifyFailed");
      if (!failed) throw e;
    }
    expect(failed).to.eq(true);
  });
});
