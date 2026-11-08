import * as anchor from "@coral-xyz/anchor";
import {
  Keypair,
  PublicKey,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, getAccount } from "@solana/spl-token";
import { createHash } from "crypto";
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
import { mldsaKeypair, mldsaSign, mldsaStream } from "./mldsa";

const PQ_MLDSA = 2;

describe("hybrid Ed25519 + ML-DSA-44 admin gate", () => {
  let f: Fixture;
  let relayer: Keypair;
  const admin = mldsaKeypair(9);
  const adminCommit = createHash("sha256").update(admin.pk).digest();
  const stranger = mldsaKeypair(10);

  before(async () => {
    f = await setupFixture(2, 3);
    relayer = Keypair.generate();
    await fund(f.provider, relayer.publicKey, 20);
    await deposit(f, usdc(500));
  });

  async function nonce(): Promise<anchor.BN> {
    return (await f.program.account.coordinator.fetch(f.coordinator)).nonce;
  }
  async function slot(): Promise<number> {
    return f.provider.connection.getSlot("confirmed");
  }
  async function send(preIxs: TransactionInstruction[], mainIx: TransactionInstruction) {
    const tx = new Transaction();
    preIxs.forEach((ix) => tx.add(ix));
    tx.add(mainIx);
    tx.feePayer = relayer.publicKey;
    tx.recentBlockhash = (await f.provider.connection.getLatestBlockhash()).blockhash;
    tx.sign(relayer);
    const sig = await f.provider.connection.sendRawTransaction(tx.serialize());
    await f.provider.connection.confirmTransaction(sig, "confirmed");
  }
  async function expectSendError(
    preIxs: TransactionInstruction[],
    mainIx: TransactionInstruction,
    code: string
  ) {
    try {
      await send(preIxs, mainIx);
    } catch (e: any) {
      const joined = (e?.logs ?? []).join("\n") + "\n" + String(e?.message ?? e);
      if (!joined.includes(code)) throw new Error(`expected ${code}, got: ${joined}`);
      return;
    }
    throw new Error(`expected error ${code} but transaction succeeded`);
  }
  const quorum = (d: Buffer) => honestQuorumInstruction([f.admins[0], f.admins[1]], d);

  async function withdrawIx(amount: anchor.BN, expiry: number, dest: PublicKey, pqState: PublicKey | null) {
    return f.program.methods
      .adminWithdraw(amount, new anchor.BN(expiry))
      .accounts({
        payer: relayer.publicKey,
        coordinator: f.coordinator,
        collateral: f.collateral,
        mint: f.mint,
        vaultTokenAccount: f.vaultAta,
        destinationTokenAccount: dest,
        tokenProgram: TOKEN_PROGRAM_ID,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        pqState,
      })
      .instruction();
  }
  function withdrawDigest(amount: anchor.BN, expiry: number, dest: PublicKey, n: anchor.BN) {
    return approvalDigest(
      ACTION_ADMIN_WITHDRAW,
      f.program.programId,
      f.coordinator,
      n,
      expiry,
      adminWithdrawParamsHash(f.collateral, dest, amount)
    );
  }

  it("enters ML-DSA hybrid mode under the Ed25519 quorum", async () => {
    const expiry = (await slot()) + 300;
    const n = await nonce();
    const digest = approvalDigest(
      ACTION_SET_PQ_MODE,
      f.program.programId,
      f.coordinator,
      n,
      expiry,
      setPqModeParamsHash(PQ_MLDSA, adminCommit)
    );
    const ix = await f.program.methods
      .setPqMode(PQ_MLDSA, Array.from(adminCommit), new anchor.BN(expiry))
      .accounts({
        payer: relayer.publicKey,
        coordinator: f.coordinator,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        pqState: null,
      })
      .instruction();
    await send([quorum(digest)], ix);
    const c = await f.program.account.coordinator.fetch(f.coordinator);
    expect(c.pqMode).to.eq(PQ_MLDSA);
  });

  it("rejects an Ed25519 quorum with no ML-DSA approval", async () => {
    const amount = usdc(100);
    const expiry = (await slot()) + 300;
    const digest = withdrawDigest(amount, expiry, f.issuerAta, await nonce());
    await expectSendError(
      [quorum(digest)],
      await withdrawIx(amount, expiry, f.issuerAta, null),
      "PqApprovalRequired"
    );
  });

  it("rejects an ML-DSA approval that has not been finalized", async () => {
    const amount = usdc(100);
    const expiry = (await slot()) + 600;
    const digest = withdrawDigest(amount, expiry, f.issuerAta, await nonce());
    const { state } = await mldsaStream(
      f.program, relayer, digest, admin.pk, mldsaSign(admin.sk, digest),
      { stopBeforeFinalize: true }
    );
    await expectSendError(
      [quorum(digest)],
      await withdrawIx(amount, expiry, f.issuerAta, state),
      "PqIncomplete"
    );
  });

  it("rejects an ML-DSA approval under a key the coordinator did not enrol", async () => {
    const amount = usdc(100);
    const expiry = (await slot()) + 600;
    const digest = withdrawDigest(amount, expiry, f.issuerAta, await nonce());
    const { state } = await mldsaStream(
      f.program, relayer, digest, stranger.pk, mldsaSign(stranger.sk, digest)
    );
    await expectSendError(
      [quorum(digest)],
      await withdrawIx(amount, expiry, f.issuerAta, state),
      "PqKeyMismatch"
    );
  });

  it("authorizes a forced withdrawal with Ed25519 AND ML-DSA-44 approval", async () => {
    const amount = usdc(100);
    const expiry = (await slot()) + 600;
    const n = await nonce();
    const digest = withdrawDigest(amount, expiry, f.issuerAta, n);
    const { state } = await mldsaStream(
      f.program, relayer, digest, admin.pk, mldsaSign(admin.sk, digest)
    );
    const before = await getAccount(f.provider.connection, f.issuerAta);
    await send([quorum(digest)], await withdrawIx(amount, expiry, f.issuerAta, state));
    const after = await getAccount(f.provider.connection, f.issuerAta);
    expect((after.amount - before.amount).toString()).to.eq(amount.toString());
    expect((await nonce()).toNumber()).to.eq(n.toNumber() + 1);
  });
});
