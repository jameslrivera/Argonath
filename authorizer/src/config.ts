import * as anchor from "@coral-xyz/anchor";
import { Keypair } from "@solana/web3.js";
import fs from "fs";
import os from "os";
import path from "path";

export interface Config {
  rpcUrl: string;
  issuer: Keypair;
  idlPath: string;
  webhookUrl: string | null;
  port: number;
  host: string;
}

function loadKeypair(p: string): Keypair {
  const resolved = p.startsWith("~") ? path.join(os.homedir(), p.slice(1)) : p;
  const bytes = JSON.parse(fs.readFileSync(resolved, "utf8"));
  return Keypair.fromSecretKey(Uint8Array.from(bytes));
}

export function loadConfig(): Config {
  const rpcUrl = process.env.RPC_URL ?? "http://127.0.0.1:8899";
  const issuerPath =
    process.env.ISSUER_KEYPAIR ?? path.join(os.homedir(), ".config/solana/id.json");
  const idlPath =
    process.env.IDL_PATH ??
    path.resolve(__dirname, "../../target/idl/collateral.json");
  const webhookUrl = process.env.WEBHOOK_URL ?? null;
  const port = Number(process.env.PORT ?? 8787);
  const host = process.env.HOST ?? "127.0.0.1";
  return { rpcUrl, issuer: loadKeypair(issuerPath), idlPath, webhookUrl, port, host };
}

export function anchorBN(n: number | string | bigint): anchor.BN {
  return new anchor.BN(n.toString());
}
