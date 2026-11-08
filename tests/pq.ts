import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { ComputeBudgetProgram, PublicKey, SystemProgram } from "@solana/web3.js";
import { expect } from "chai";
import fs from "fs";
import path from "path";
import { Collateral } from "../target/types/collateral";
import { LEN, publicKeyCommit, secretKey, sha256, sign } from "./wots";

const CHUNK = 16;

function pqStatePda(
  program: Program<Collateral>,
  authority: PublicKey,
  digest: Buffer
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("pq"), authority.toBuffer(), digest],
    program.programId
  )[0];
}

describe("post-quantum WOTS streaming verifier", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Collateral as Program<Collateral>;
  const authority = provider.wallet.publicKey;

  async function cuOf(sig: string): Promise<number> {
    for (let attempt = 0; attempt < 20; attempt++) {
      const tx = await provider.connection.getTransaction(sig, {
        commitment: "confirmed",
        maxSupportedTransactionVersion: 0,
      });
      const cu = tx?.meta?.computeUnitsConsumed;
      if (cu !== undefined && cu !== null) return cu;
      await new Promise((r) => setTimeout(r, 300));
    }
    return 0;
  }

  async function streamVerify(
    digest: Buffer,
    sigChains: Buffer[],
    pkCommit: Buffer
  ): Promise<{ chunkCu: number[]; finalizeCu: number; state: PublicKey }> {
    const state = pqStatePda(program, authority, digest);
    await program.methods
      .pqOpen(Array.from(digest), Array.from(pkCommit))
      .accounts({
        authority,
        state,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const chunkCu: number[] = [];
    for (let start = 0; start < LEN; start += CHUNK) {
      const slice = sigChains
        .slice(start, Math.min(start + CHUNK, LEN))
        .map((b) => Array.from(b));
      const sig = await program.methods
        .pqVerifyChunk(start, slice)
        .accounts({ authority, state })
        .preInstructions([
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
        ])
        .rpc();
      chunkCu.push(await cuOf(sig));
    }

    const finalSig = await program.methods
      .pqFinalize()
      .accounts({ authority, state })
      .rpc();
    const finalizeCu = await cuOf(finalSig);
    return { chunkCu, finalizeCu, state };
  }

  it("verifies a valid WOTS signature across chunks and records CU", async () => {
    const sk = secretKey(42);
    const pkCommit = publicKeyCommit(sk);
    const digest = sha256(Buffer.from("PQVAULT quantum-safe forced withdrawal " + Date.now()));
    const sigChains = sign(sk, digest);

    const { chunkCu, finalizeCu, state } = await streamVerify(
      digest,
      sigChains,
      pkCommit
    );

    const acc = await program.account.pqVerifyState.fetch(state);
    expect(acc.done).to.eq(true);

    const totalVerify = chunkCu.reduce((a, b) => a + b, 0) + finalizeCu;
    const maxChunk = Math.max(...chunkCu);

    const rows = [
      "scheme,metric,value",
      "WOTS-SHA256-w16,chains,67",
      "WOTS-SHA256-w16,signature_bytes," + LEN * 32,
      "WOTS-SHA256-w16,chunk_size," + CHUNK,
      "WOTS-SHA256-w16,chunks," + chunkCu.length,
      ...chunkCu.map((cu, i) => `WOTS-SHA256-w16,chunk_${i}_cu,${cu}`),
      "WOTS-SHA256-w16,max_chunk_cu," + maxChunk,
      "WOTS-SHA256-w16,finalize_cu," + finalizeCu,
      "WOTS-SHA256-w16,total_verify_cu," + totalVerify,
      "WOTS-SHA256-w16,transactions," + (chunkCu.length + 1),
    ];
    const outDir = path.resolve(__dirname, "../bench");
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(path.join(outDir, "results.csv"), rows.join("\n") + "\n");

    expect(maxChunk).to.be.lessThan(1_400_000);
    console.log(
      `    WOTS verify: ${chunkCu.length} chunks, max chunk ${maxChunk} CU, total ${totalVerify} CU`
    );
  });

  it("rejects a tampered signature at finalize", async () => {
    const sk = secretKey(99);
    const pkCommit = publicKeyCommit(sk);
    const digest = sha256(Buffer.from("tamper test " + Date.now()));
    const sigChains = sign(sk, digest);
    const bad = sigChains.map((b) => Buffer.from(b));
    bad[5] = Buffer.from(sha256(bad[5]));

    const state = pqStatePda(program, authority, digest);
    await program.methods
      .pqOpen(Array.from(digest), Array.from(pkCommit))
      .accounts({ authority, state, systemProgram: SystemProgram.programId })
      .rpc();
    for (let start = 0; start < LEN; start += CHUNK) {
      const slice = bad
        .slice(start, Math.min(start + CHUNK, LEN))
        .map((b) => Array.from(b));
      await program.methods
        .pqVerifyChunk(start, slice)
        .accounts({ authority, state })
        .preInstructions([
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
        ])
        .rpc();
    }
    let failed = false;
    try {
      await program.methods.pqFinalize().accounts({ authority, state }).rpc();
    } catch (e: any) {
      failed = String(e).includes("PqCommitmentMismatch");
    }
    expect(failed).to.eq(true);
  });
});
