import * as anchor from "@coral-xyz/anchor";
import { Keypair, PublicKey } from "@solana/web3.js";
import fs from "fs";
import os from "os";
import path from "path";
import {
  ACTION_ADMIN_WITHDRAW,
  ACTION_ROTATE_ADMINS,
  ACTION_SET_PQ_MODE,
  adminWithdrawParamsHash,
  approvalDigest,
  honestQuorumInstruction,
  rotateAdminsParamsHash,
  setPqModeParamsHash,
} from "./quorum";

function parseArgs(argv: string[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      const key = argv[i].slice(2);
      const val = argv[i + 1];
      if (!out.has(key)) out.set(key, []);
      out.get(key)!.push(val);
      i++;
    }
  }
  return out;
}

function one(args: Map<string, string[]>, key: string): string {
  const v = args.get(key);
  if (!v || v.length === 0) throw new Error(`missing --${key}`);
  return v[0];
}

function loadKeypair(p: string): Keypair {
  const resolved = p.startsWith("~") ? path.join(os.homedir(), p.slice(1)) : p;
  const bytes = JSON.parse(fs.readFileSync(resolved, "utf8"));
  return Keypair.fromSecretKey(Uint8Array.from(bytes));
}

function main() {
  const [, , action, ...rest] = process.argv;
  const args = parseArgs(rest);
  const program = new PublicKey(one(args, "program"));
  const coordinator = new PublicKey(one(args, "coordinator"));
  const nonce = new anchor.BN(one(args, "nonce"));
  const expiry = new anchor.BN(one(args, "expiry"));
  const adminPaths = args.get("admin") ?? [];
  if (adminPaths.length === 0) throw new Error("provide at least one --admin keypair");
  const admins = adminPaths.map(loadKeypair);

  let tag: number;
  let paramsHash: Buffer;

  if (action === "admin-withdraw") {
    const collateral = new PublicKey(one(args, "collateral"));
    const destination = new PublicKey(one(args, "destination"));
    const amount = new anchor.BN(one(args, "amount"));
    tag = ACTION_ADMIN_WITHDRAW;
    paramsHash = adminWithdrawParamsHash(collateral, destination, amount);
  } else if (action === "rotate-admins") {
    const newAdmins = (args.get("new-admin") ?? []).map((p) => new PublicKey(p));
    const threshold = Number(one(args, "new-threshold"));
    tag = ACTION_ROTATE_ADMINS;
    paramsHash = rotateAdminsParamsHash(newAdmins, threshold);
  } else if (action === "set-pq-mode") {
    const mode = Number(one(args, "mode"));
    const pkCommit = Buffer.from(one(args, "pk-commit"), "hex");
    if (pkCommit.length !== 32) throw new Error("--pk-commit must be 32 bytes of hex");
    tag = ACTION_SET_PQ_MODE;
    paramsHash = setPqModeParamsHash(mode, pkCommit);
  } else {
    throw new Error(
      `unknown action: ${action} (use admin-withdraw, rotate-admins or set-pq-mode)`
    );
  }

  const digest = approvalDigest(tag, program, coordinator, nonce, expiry, paramsHash);
  const ed = honestQuorumInstruction(admins, digest);

  process.stdout.write(
    JSON.stringify(
      {
        action,
        nonce: nonce.toString(),
        expirySlot: expiry.toString(),
        digestHex: digest.toString("hex"),
        signers: admins.map((a) => a.publicKey.toBase58()),
        ed25519InstructionBase64: ed.data.toString("base64"),
      },
      null,
      2
    ) + "\n"
  );
}

main();
