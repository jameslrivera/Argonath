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

export function honestQuorumInstruction(
  signers: Keypair[],
  digest: Buffer
): TransactionInstruction {
  const count = signers.length;
  const header = Buffer.alloc(HEADER_SIZE);
  header.writeUInt8(count, 0);
  const offsets = Buffer.alloc(count * ENTRY_SIZE);
  const payloads: Buffer[] = [];
  let cursor = HEADER_SIZE + count * ENTRY_SIZE;
  const layout: { sigOff: number; pkOff: number; msgOff: number }[] = [];
  for (const kp of signers) {
    const sig = Buffer.from(nacl.sign.detached(digest, kp.secretKey));
    const pk = Buffer.from(kp.publicKey.toBytes());
    const sigOff = cursor;
    payloads.push(sig);
    cursor += sig.length;
    const pkOff = cursor;
    payloads.push(pk);
    cursor += pk.length;
    const msgOff = cursor;
    payloads.push(digest);
    cursor += digest.length;
    layout.push({ sigOff, pkOff, msgOff });
  }
  for (let i = 0; i < count; i++) {
    const base = i * ENTRY_SIZE;
    const l = layout[i];
    offsets.writeUInt16LE(l.sigOff, base);
    offsets.writeUInt16LE(SELF, base + 2);
    offsets.writeUInt16LE(l.pkOff, base + 4);
    offsets.writeUInt16LE(SELF, base + 6);
    offsets.writeUInt16LE(l.msgOff, base + 8);
    offsets.writeUInt16LE(digest.length, base + 10);
    offsets.writeUInt16LE(SELF, base + 12);
  }
  const data = Buffer.concat([header, offsets, ...payloads]);
  return new TransactionInstruction({
    keys: [],
    programId: Ed25519Program.programId,
    data,
  });
}
