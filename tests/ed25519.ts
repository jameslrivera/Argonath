import * as anchor from "@coral-xyz/anchor";
import {
  Ed25519Program,
  Keypair,
  PublicKey,
  TransactionInstruction,
} from "@solana/web3.js";
import { createHash } from "crypto";
import nacl from "tweetnacl";

const DOMAIN = Buffer.from("PQVAULT_QUORUM_V1");
export const ACTION_ADMIN_WITHDRAW = 1;
export const ACTION_ROTATE_ADMINS = 2;
export const ACTION_SET_PQ_MODE = 3;

const HEADER_SIZE = 2;
const ENTRY_SIZE = 14;
const SIG_SIZE = 64;
const SELF = 0xffff;

function sha256(...parts: Buffer[]): Buffer {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

function u64le(n: anchor.BN | number): Buffer {
  return new anchor.BN(n).toArrayLike(Buffer, "le", 8);
}

export function adminWithdrawParamsHash(
  collateral: PublicKey,
  destination: PublicKey,
  amount: anchor.BN
): Buffer {
  return sha256(collateral.toBuffer(), destination.toBuffer(), u64le(amount));
}

export function rotateAdminsParamsHash(
  admins: PublicKey[],
  threshold: number
): Buffer {
  return sha256(...admins.map((a) => a.toBuffer()), Buffer.from([threshold]));
}

export function setPqModeParamsHash(mode: number, pkCommit: Buffer): Buffer {
  return sha256(Buffer.from([mode]), pkCommit);
}

export function approvalDigest(
  actionTag: number,
  programId: PublicKey,
  coordinator: PublicKey,
  nonce: anchor.BN | number,
  expirySlot: anchor.BN | number,
  paramsHash: Buffer
): Buffer {
  return sha256(
    DOMAIN,
    Buffer.from([actionTag]),
    programId.toBuffer(),
    coordinator.toBuffer(),
    u64le(nonce),
    u64le(expirySlot),
    paramsHash
  );
}

interface Entry {
  publicKey: Buffer;
  signature: Buffer;
  message: Buffer;
  sigIxIndex: number;
  pkIxIndex: number;
  msgIxIndex: number;
}

function buildEd25519Instruction(entries: Entry[]): TransactionInstruction {
  const count = entries.length;
  const header = Buffer.alloc(HEADER_SIZE);
  header.writeUInt8(count, 0);
  const offsets = Buffer.alloc(count * ENTRY_SIZE);
  const payloads: Buffer[] = [];
  let cursor = HEADER_SIZE + count * ENTRY_SIZE;
  const layout: { sigOff: number; pkOff: number; msgOff: number; msgSize: number }[] = [];
  for (const e of entries) {
    const sigOff = cursor;
    payloads.push(e.signature);
    cursor += e.signature.length;
    const pkOff = cursor;
    payloads.push(e.publicKey);
    cursor += e.publicKey.length;
    const msgOff = cursor;
    payloads.push(e.message);
    cursor += e.message.length;
    layout.push({ sigOff, pkOff, msgOff, msgSize: e.message.length });
  }
  for (let i = 0; i < count; i++) {
    const base = i * ENTRY_SIZE;
    const e = entries[i];
    const l = layout[i];
    offsets.writeUInt16LE(l.sigOff, base);
    offsets.writeUInt16LE(e.sigIxIndex, base + 2);
    offsets.writeUInt16LE(l.pkOff, base + 4);
    offsets.writeUInt16LE(e.pkIxIndex, base + 6);
    offsets.writeUInt16LE(l.msgOff, base + 8);
    offsets.writeUInt16LE(l.msgSize, base + 10);
    offsets.writeUInt16LE(e.msgIxIndex, base + 12);
  }
  const data = Buffer.concat([header, offsets, ...payloads]);
  return new TransactionInstruction({
    keys: [],
    programId: Ed25519Program.programId,
    data,
  });
}

export function honestQuorumInstruction(
  signers: Keypair[],
  digest: Buffer
): TransactionInstruction {
  const entries: Entry[] = signers.map((kp) => ({
    publicKey: Buffer.from(kp.publicKey.toBytes()),
    signature: Buffer.from(nacl.sign.detached(digest, kp.secretKey)),
    message: digest,
    sigIxIndex: SELF,
    pkIxIndex: SELF,
    msgIxIndex: SELF,
  }));
  return buildEd25519Instruction(entries);
}

export function forgedQuorumInstructions(
  adminPubkeys: PublicKey[],
  digest: Buffer
): { decoyIx: TransactionInstruction; forgedIx: TransactionInstruction } {
  const decoy = Keypair.generate();
  const decoySig = Buffer.from(nacl.sign.detached(digest, decoy.secretKey));
  const decoyEntries: Entry[] = adminPubkeys.map(() => ({
    publicKey: Buffer.from(decoy.publicKey.toBytes()),
    signature: decoySig,
    message: digest,
    sigIxIndex: SELF,
    pkIxIndex: SELF,
    msgIxIndex: SELF,
  }));
  const forgedEntries: Entry[] = adminPubkeys.map((pk) => ({
    publicKey: Buffer.from(pk.toBytes()),
    signature: Buffer.alloc(SIG_SIZE, 0x09),
    message: digest,
    sigIxIndex: 0,
    pkIxIndex: 0,
    msgIxIndex: 0,
  }));
  return {
    decoyIx: buildEd25519Instruction(decoyEntries),
    forgedIx: buildEd25519Instruction(forgedEntries),
  };
}

export { SIG_SIZE, SELF };
