import Fastify from "fastify";
import { PublicKey } from "@solana/web3.js";
import { getAssociatedTokenAddressSync } from "@solana/spl-token";
import { anchorBN, loadConfig } from "./config";
import { VaultClient } from "./vault";
import { emitWebhook } from "./webhooks";

function pk(value: unknown, field: string): PublicKey {
  if (typeof value !== "string") throw new Error(`missing ${field}`);
  return new PublicKey(value);
}

function merchantRef(value: unknown): number[] {
  if (typeof value !== "string") return Array(32).fill(0);
  const buf = Buffer.alloc(32);
  Buffer.from(value).copy(buf, 0, 0, 32);
  return Array.from(buf);
}

async function main() {
  const cfg = loadConfig();
  const client = new VaultClient(cfg);
  const app = Fastify({ logger: true });

  app.get("/health", async () => ({
    ok: true,
    programId: client.programId.toBase58(),
    coordinator: client.coordinator().toBase58(),
  }));

  app.get<{ Params: { owner: string; mint: string } }>(
    "/vault/:owner/:mint",
    async (req, reply) => {
      try {
        const owner = new PublicKey(req.params.owner);
        const mint = new PublicKey(req.params.mint);
        return await client.vaultState(owner, mint);
      } catch (e: any) {
        reply.code(404);
        return { error: String(e?.message ?? e) };
      }
    }
  );

  app.post("/authorize", async (req, reply) => {
    try {
      const b = req.body as Record<string, unknown>;
      const owner = pk(b.owner, "owner");
      const mint = pk(b.mint, "mint");
      const amount = anchorBN(b.amount as string);
      const slot = await client.slot();
      const expirySlot = anchorBN(slot + Number(b.expirySlots ?? 150));
      const res = await client.authorize(
        owner,
        mint,
        amount,
        expirySlot,
        merchantRef(b.merchantRef)
      );
      emitWebhook(cfg.webhookUrl, "authorization.created", {
        owner: owner.toBase58(),
        mint: mint.toBase58(),
        amount: amount.toString(),
        ...res,
      });
      return res;
    } catch (e: any) {
      reply.code(400);
      return { error: String(e?.message ?? e) };
    }
  });

  app.post("/settle", async (req, reply) => {
    try {
      const b = req.body as Record<string, unknown>;
      const owner = pk(b.owner, "owner");
      const mint = pk(b.mint, "mint");
      const holdId = anchorBN(b.holdId as string);
      const amount = anchorBN(b.amount as string);
      const issuerAta = getAssociatedTokenAddressSync(
        mint,
        client.issuer.publicKey
      );
      const signature = await client.settle(
        owner,
        mint,
        holdId,
        amount,
        issuerAta
      );
      emitWebhook(cfg.webhookUrl, "settlement.completed", {
        owner: owner.toBase58(),
        mint: mint.toBase58(),
        holdId: holdId.toString(),
        amount: amount.toString(),
        signature,
      });
      return { signature };
    } catch (e: any) {
      reply.code(400);
      return { error: String(e?.message ?? e) };
    }
  });

  app.post("/release", async (req, reply) => {
    try {
      const b = req.body as Record<string, unknown>;
      const owner = pk(b.owner, "owner");
      const mint = pk(b.mint, "mint");
      const holdId = anchorBN(b.holdId as string);
      const signature = await client.release(owner, mint, holdId);
      emitWebhook(cfg.webhookUrl, "hold.released", {
        owner: owner.toBase58(),
        mint: mint.toBase58(),
        holdId: holdId.toString(),
        signature,
      });
      return { signature };
    } catch (e: any) {
      reply.code(400);
      return { error: String(e?.message ?? e) };
    }
  });

  await app.listen({ port: cfg.port, host: cfg.host });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
