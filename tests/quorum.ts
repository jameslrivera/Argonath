import * as anchor from "@coral-xyz/anchor";
import {
  Keypair,
  PublicKey,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, getAccount } from "@solana/spl-token";
import { expect } from "chai";
import { Fixture, deposit, fund, setupFixture, usdc } from "./helpers";
import {
  ACTION_ADMIN_WITHDRAW,
  ACTION_ROTATE_ADMINS,
  adminWithdrawParamsHash,
  approvalDigest,
  forgedQuorumInstructions,
  honestQuorumInstruction,
  rotateAdminsParamsHash,
} from "./ed25519";

async function send(
  f: Fixture,
  relayer: Keypair,
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
  const raw = tx.serialize();
  const sig = await f.provider.connection.sendRawTransaction(raw, {
    skipPreflight: false,
  });
  await f.provider.connection.confirmTransaction(sig, "confirmed");
}

async function expectSendError(
  f: Fixture,
  relayer: Keypair,
  preIxs: TransactionInstruction[],
  mainIx: TransactionInstruction,
  code: string
): Promise<void> {
  try {
    await send(f, relayer, preIxs, mainIx);
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

describe("ed25519 admin quorum", () => {
  let f: Fixture;
  let relayer: Keypair;

  async function nonce(): Promise<anchor.BN> {
    return (await f.program.account.coordinator.fetch(f.coordinator)).nonce;
  }
  async function slot(): Promise<number> {
    return f.provider.connection.getSlot("confirmed");
  }

  async function withdrawIx(
    amount: anchor.BN,
    expiry: number,
    destination: PublicKey
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
        pqState: null,
      })
      .instruction();
  }

  async function withdrawDigest(
    amount: anchor.BN,
    expiry: number,
    destination: PublicKey,
    n: anchor.BN
  ): Promise<Buffer> {
    const ph = adminWithdrawParamsHash(f.collateral, destination, amount);
    return approvalDigest(
      ACTION_ADMIN_WITHDRAW,
      f.program.programId,
      f.coordinator,
      n,
      expiry,
      ph
    );
  }

  before(async () => {
    f = await setupFixture(2, 3);
    relayer = Keypair.generate();
    await fund(f.provider, relayer.publicKey, 5);
    await deposit(f, usdc(500));
  });

  it("honest 2-of-3 quorum authorizes a forced withdrawal", async () => {
    const amount = usdc(100);
    const expiry = (await slot()) + 150;
    const n = await nonce();
    const digest = await withdrawDigest(amount, expiry, f.issuerAta, n);
    const ed = honestQuorumInstruction([f.admins[0], f.admins[1]], digest);
    const ix = await withdrawIx(amount, expiry, f.issuerAta);
    const before = await getAccount(f.provider.connection, f.issuerAta);
    await send(f, relayer, [ed], ix);
    const after = await getAccount(f.provider.connection, f.issuerAta);
    expect((after.amount - before.amount).toString()).to.eq(amount.toString());
    const col = await f.program.account.collateral.fetch(f.collateral);
    expect(col.deposited.toString()).to.eq(usdc(400).toString());
    expect((await nonce()).toNumber()).to.eq(n.toNumber() + 1);
  });

  it("rejects a forged quorum (the Rain bug)", async () => {
    const amount = usdc(50);
    const expiry = (await slot()) + 150;
    const n = await nonce();
    const digest = await withdrawDigest(amount, expiry, f.issuerAta, n);
    const { decoyIx, forgedIx } = forgedQuorumInstructions(
      f.admins.slice(0, 2).map((a) => a.publicKey),
      digest
    );
    const ix = await withdrawIx(amount, expiry, f.issuerAta);
    await expectSendError(
      f,
      relayer,
      [decoyIx, forgedIx],
      ix,
      "InvalidSignatureEntry"
    );
    expect((await nonce()).toNumber()).to.eq(n.toNumber());
  });

  it("rejects a replayed approval", async () => {
    const amount = usdc(30);
    const expiry = (await slot()) + 150;
    const n = await nonce();
    const digest = await withdrawDigest(amount, expiry, f.issuerAta, n);
    const ed = honestQuorumInstruction([f.admins[0], f.admins[1]], digest);
    await send(f, relayer, [ed], await withdrawIx(amount, expiry, f.issuerAta));
    await expectSendError(
      f,
      relayer,
      [ed],
      await withdrawIx(amount, expiry, f.issuerAta),
      "MessageMismatch"
    );
  });

  it("rejects an approval signed for a different action", async () => {
    const amount = usdc(30);
    const expiry = (await slot()) + 150;
    const n = await nonce();
    const ph = adminWithdrawParamsHash(f.collateral, f.issuerAta, amount);
    const wrong = approvalDigest(
      ACTION_ROTATE_ADMINS,
      f.program.programId,
      f.coordinator,
      n,
      expiry,
      ph
    );
    const ed = honestQuorumInstruction([f.admins[0], f.admins[1]], wrong);
    await expectSendError(
      f,
      relayer,
      [ed],
      await withdrawIx(amount, expiry, f.issuerAta),
      "MessageMismatch"
    );
  });

  it("rejects a non-admin signer", async () => {
    const amount = usdc(30);
    const expiry = (await slot()) + 150;
    const n = await nonce();
    const digest = await withdrawDigest(amount, expiry, f.issuerAta, n);
    const outsider = Keypair.generate();
    const ed = honestQuorumInstruction([f.admins[0], outsider], digest);
    await expectSendError(
      f,
      relayer,
      [ed],
      await withdrawIx(amount, expiry, f.issuerAta),
      "NotAnAdmin"
    );
  });

  it("rejects below-threshold signatures", async () => {
    const amount = usdc(30);
    const expiry = (await slot()) + 150;
    const n = await nonce();
    const digest = await withdrawDigest(amount, expiry, f.issuerAta, n);
    const ed = honestQuorumInstruction([f.admins[0]], digest);
    await expectSendError(
      f,
      relayer,
      [ed],
      await withdrawIx(amount, expiry, f.issuerAta),
      "QuorumNotMet"
    );
  });

  it("rejects a duplicate admin signature", async () => {
    const amount = usdc(30);
    const expiry = (await slot()) + 150;
    const n = await nonce();
    const digest = await withdrawDigest(amount, expiry, f.issuerAta, n);
    const ed = honestQuorumInstruction([f.admins[0], f.admins[0]], digest);
    await expectSendError(
      f,
      relayer,
      [ed],
      await withdrawIx(amount, expiry, f.issuerAta),
      "DuplicateSignature"
    );
  });

  it("rejects an expired approval", async () => {
    const amount = usdc(30);
    const expiry = 1;
    const n = await nonce();
    const digest = await withdrawDigest(amount, expiry, f.issuerAta, n);
    const ed = honestQuorumInstruction([f.admins[0], f.admins[1]], digest);
    await expectSendError(
      f,
      relayer,
      [ed],
      await withdrawIx(amount, expiry, f.issuerAta),
      "ApprovalExpired"
    );
  });

  it("rotates the admin set under quorum", async () => {
    const newAdmins = [
      f.admins[0].publicKey,
      f.admins[1].publicKey,
      f.admins[2].publicKey,
      Keypair.generate().publicKey,
    ];
    const newThreshold = 3;
    const expiry = (await slot()) + 150;
    const n = await nonce();
    const ph = rotateAdminsParamsHash(newAdmins, newThreshold);
    const digest = approvalDigest(
      ACTION_ROTATE_ADMINS,
      f.program.programId,
      f.coordinator,
      n,
      expiry,
      ph
    );
    const ed = honestQuorumInstruction([f.admins[0], f.admins[1]], digest);
    const ix = await f.program.methods
      .rotateAdmins(newAdmins, newThreshold, new anchor.BN(expiry))
      .accounts({
        payer: relayer.publicKey,
        coordinator: f.coordinator,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        pqState: null,
      })
      .instruction();
    await send(f, relayer, [ed], ix);
    const c = await f.program.account.coordinator.fetch(f.coordinator);
    expect(c.admins.length).to.eq(4);
    expect(c.threshold).to.eq(3);
  });
});
