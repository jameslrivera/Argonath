import * as anchor from "@coral-xyz/anchor";
import {
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, getAccount } from "@solana/spl-token";
import { expect } from "chai";
import { Fixture, deposit, fund, setupFixture, usdc } from "./helpers";
import {
  ACTION_ADMIN_WITHDRAW,
  ACTION_SET_PQ_MODE,
  adminWithdrawParamsHash,
  approvalDigest,
  honestQuorumInstruction,
  setPqModeParamsHash,
} from "./ed25519";
import { LEN, publicKeyCommit, secretKey, sign } from "./wots";

const CHUNK = 16;
const PQ_OFF = 0;
const PQ_HYBRID = 1;

describe("hybrid Ed25519 + post-quantum admin gate", () => {
  let f: Fixture;
  let relayer: Keypair;
  const pqSk = secretKey(1);
  const pqCommit = publicKeyCommit(pqSk);
  const pqSk2 = secretKey(2);
  const pqCommit2 = publicKeyCommit(pqSk2);

  before(async () => {
    f = await setupFixture(2, 3);
    relayer = Keypair.generate();
    await fund(f.provider, relayer.publicKey, 5);
    await deposit(f, usdc(500));
  });

  async function nonce(): Promise<anchor.BN> {
    return (await f.program.account.coordinator.fetch(f.coordinator)).nonce;
  }
  async function slot(): Promise<number> {
    return f.provider.connection.getSlot("confirmed");
  }

  async function send(
    preIxs: TransactionInstruction[],
    mainIx: TransactionInstruction
  ): Promise<void> {
    const tx = new Transaction();
    preIxs.forEach((ix) => tx.add(ix));
    tx.add(mainIx);
    tx.feePayer = relayer.publicKey;
    tx.recentBlockhash = (
      await f.provider.connection.getLatestBlockhash()
    ).blockhash;
    tx.sign(relayer);
    const sig = await f.provider.connection.sendRawTransaction(tx.serialize());
    await f.provider.connection.confirmTransaction(sig, "confirmed");
  }

  async function expectSendError(
    preIxs: TransactionInstruction[],
    mainIx: TransactionInstruction,
    code: string
  ): Promise<void> {
    try {
      await send(preIxs, mainIx);
    } catch (e: any) {
      const logs: string[] = e?.logs ?? [];
      const joined = logs.join("\n") + "\n" + String(e?.message ?? e);
      if (!joined.includes(code)) {
        throw new Error(`expected ${code}, got: ${joined}`);
      }
      return;
    }
    throw new Error(`expected error ${code} but transaction succeeded`);
  }

  function pqStatePda(digest: Buffer): PublicKey {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("pq"), relayer.publicKey.toBuffer(), digest],
      f.program.programId
    )[0];
  }

  async function pqOpen(digest: Buffer, commit: Buffer): Promise<PublicKey> {
    const state = pqStatePda(digest);
    await f.program.methods
      .pqOpen(Array.from(digest), Array.from(commit))
      .accounts({
        authority: relayer.publicKey,
        state,
        systemProgram: SystemProgram.programId,
      })
      .signers([relayer])
      .rpc();
    return state;
  }

  async function pqChunks(
    state: PublicKey,
    digest: Buffer,
    sk: Buffer[],
    maxChunks = Infinity
  ): Promise<void> {
    const chains = sign(sk, digest);
    let sent = 0;
    for (let start = 0; start < LEN && sent < maxChunks; start += CHUNK, sent++) {
      const slice = chains
        .slice(start, Math.min(start + CHUNK, LEN))
        .map((b) => Array.from(b));
      await f.program.methods
        .pqVerifyChunk(start, slice)
        .accounts({ authority: relayer.publicKey, state })
        .preInstructions([
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
        ])
        .signers([relayer])
        .rpc();
    }
  }

  async function pqFinalize(state: PublicKey): Promise<void> {
    await f.program.methods
      .pqFinalize()
      .accounts({ authority: relayer.publicKey, state })
      .signers([relayer])
      .rpc();
  }

  async function pqApprove(
    digest: Buffer,
    sk: Buffer[] = pqSk,
    commit: Buffer = pqCommit
  ): Promise<PublicKey> {
    const state = await pqOpen(digest, commit);
    await pqChunks(state, digest, sk);
    await pqFinalize(state);
    return state;
  }

  async function withdrawIx(
    amount: anchor.BN,
    expiry: number,
    destination: PublicKey,
    pqState: PublicKey | null
  ): Promise<TransactionInstruction> {
    return f.program.methods
      .adminWithdraw(amount, new anchor.BN(expiry))
      .accounts({
        payer: relayer.publicKey,
        coordinator: f.coordinator,
        collateral: f.collateral,
        mint: f.mint,
        vaultTokenAccount: f.vaultAta,
        destinationTokenAccount: destination,
        tokenProgram: TOKEN_PROGRAM_ID,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        pqState,
      })
      .instruction();
  }

  function withdrawDigest(
    amount: anchor.BN,
    expiry: number,
    destination: PublicKey,
    n: anchor.BN
  ): Buffer {
    return approvalDigest(
      ACTION_ADMIN_WITHDRAW,
      f.program.programId,
      f.coordinator,
      n,
      expiry,
      adminWithdrawParamsHash(f.collateral, destination, amount)
    );
  }

  async function setPqModeIx(
    mode: number,
    commit: Buffer,
    expiry: number,
    pqState: PublicKey | null
  ): Promise<TransactionInstruction> {
    return f.program.methods
      .setPqMode(mode, Array.from(commit), new anchor.BN(expiry))
      .accounts({
        payer: relayer.publicKey,
        coordinator: f.coordinator,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        pqState,
      })
      .instruction();
  }

  function setPqModeDigest(
    mode: number,
    commit: Buffer,
    expiry: number,
    n: anchor.BN
  ): Buffer {
    return approvalDigest(
      ACTION_SET_PQ_MODE,
      f.program.programId,
      f.coordinator,
      n,
      expiry,
      setPqModeParamsHash(mode, commit)
    );
  }

  const quorum = (digest: Buffer) =>
    honestQuorumInstruction([f.admins[0], f.admins[1]], digest);

  it("starts in Ed25519-only mode", async () => {
    const c = await f.program.account.coordinator.fetch(f.coordinator);
    expect(c.pqMode).to.eq(PQ_OFF);
  });

  it("enters hybrid mode under the Ed25519 quorum", async () => {
    const expiry = (await slot()) + 150;
    const n = await nonce();
    const digest = setPqModeDigest(PQ_HYBRID, pqCommit, expiry, n);
    await send([quorum(digest)], await setPqModeIx(PQ_HYBRID, pqCommit, expiry, null));
    const c = await f.program.account.coordinator.fetch(f.coordinator);
    expect(c.pqMode).to.eq(PQ_HYBRID);
    expect(Buffer.from(c.pqPkCommit).equals(pqCommit)).to.eq(true);
    expect((await nonce()).toNumber()).to.eq(n.toNumber() + 1);
  });

  it("rejects an Ed25519 quorum with no post-quantum approval", async () => {
    const amount = usdc(100);
    const expiry = (await slot()) + 150;
    const n = await nonce();
    const digest = withdrawDigest(amount, expiry, f.issuerAta, n);
    await expectSendError(
      [quorum(digest)],
      await withdrawIx(amount, expiry, f.issuerAta, null),
      "PqApprovalRequired"
    );
    expect((await nonce()).toNumber()).to.eq(n.toNumber());
  });

  it("rejects an unfinished post-quantum approval", async () => {
    const amount = usdc(100);
    const expiry = (await slot()) + 300;
    const n = await nonce();
    const digest = withdrawDigest(amount, expiry, f.issuerAta, n);
    const state = await pqOpen(digest, pqCommit);
    await pqChunks(state, digest, pqSk, 2);
    await expectSendError(
      [quorum(digest)],
      await withdrawIx(amount, expiry, f.issuerAta, state),
      "PqIncomplete"
    );
  });

  it("rejects a post-quantum approval over a different message", async () => {
    const amount = usdc(100);
    const expiry = (await slot()) + 300;
    const n = await nonce();
    const other = withdrawDigest(usdc(400), expiry, f.issuerAta, n);
    const state = await pqApprove(other);
    const digest = withdrawDigest(amount, expiry, f.issuerAta, n);
    await expectSendError(
      [quorum(digest)],
      await withdrawIx(amount, expiry, f.issuerAta, state),
      "PqDigestMismatch"
    );
  });

  it("rejects a post-quantum approval under a different key", async () => {
    const amount = usdc(100);
    const expiry = (await slot()) + 300;
    const n = await nonce();
    const digest = withdrawDigest(amount, expiry, f.issuerAta, n);
    const state = await pqApprove(digest, pqSk2, pqCommit2);
    await expectSendError(
      [quorum(digest)],
      await withdrawIx(amount, expiry, f.issuerAta, state),
      "PqKeyMismatch"
    );
  });

  it("authorizes a forced withdrawal with Ed25519 AND post-quantum approval", async () => {
    const amount = usdc(100);
    const expiry = (await slot()) + 300;
    const n = await nonce();
    const digest = withdrawDigest(amount, expiry, f.issuerAta, n);
    const state = await pqApprove(digest);
    const before = await getAccount(f.provider.connection, f.issuerAta);
    await send([quorum(digest)], await withdrawIx(amount, expiry, f.issuerAta, state));
    const after = await getAccount(f.provider.connection, f.issuerAta);
    expect((after.amount - before.amount).toString()).to.eq(amount.toString());
    const col = await f.program.account.collateral.fetch(f.collateral);
    expect(col.deposited.toString()).to.eq(usdc(400).toString());
    expect((await nonce()).toNumber()).to.eq(n.toNumber() + 1);
  });

  it("rotates the post-quantum key under a hybrid approval", async () => {
    const expiry = (await slot()) + 300;
    const n = await nonce();
    const digest = setPqModeDigest(PQ_HYBRID, pqCommit2, expiry, n);
    const state = await pqApprove(digest);
    await send([quorum(digest)], await setPqModeIx(PQ_HYBRID, pqCommit2, expiry, state));
    const c = await f.program.account.coordinator.fetch(f.coordinator);
    expect(Buffer.from(c.pqPkCommit).equals(pqCommit2)).to.eq(true);
  });

  it("leaving hybrid mode also requires a post-quantum approval", async () => {
    const expiry = (await slot()) + 300;
    const n = await nonce();
    const digest = setPqModeDigest(PQ_OFF, pqCommit2, expiry, n);
    await expectSendError(
      [quorum(digest)],
      await setPqModeIx(PQ_OFF, pqCommit2, expiry, null),
      "PqApprovalRequired"
    );
    const state = await pqApprove(digest, pqSk2, pqCommit2);
    await send([quorum(digest)], await setPqModeIx(PQ_OFF, pqCommit2, expiry, state));
    const c = await f.program.account.coordinator.fetch(f.coordinator);
    expect(c.pqMode).to.eq(PQ_OFF);
  });
});
