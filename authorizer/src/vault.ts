import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  getAssociatedTokenAddressSync,
} from "@solana/spl-token";
import fs from "fs";
import { Config } from "./config";

export class VaultClient {
  readonly program: Program;
  readonly connection: Connection;
  readonly issuer: Keypair;
  readonly programId: PublicKey;

  constructor(cfg: Config) {
    const idl = JSON.parse(fs.readFileSync(cfg.idlPath, "utf8"));
    this.connection = new Connection(cfg.rpcUrl, "confirmed");
    this.issuer = cfg.issuer;
    const wallet = new anchor.Wallet(cfg.issuer);
    const provider = new anchor.AnchorProvider(this.connection, wallet, {
      commitment: "confirmed",
    });
    this.program = new Program(idl, provider);
    this.programId = this.program.programId;
  }

  coordinator(): PublicKey {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("coordinator"), this.issuer.publicKey.toBuffer()],
      this.programId
    )[0];
  }

  collateral(owner: PublicKey, mint: PublicKey): PublicKey {
    return PublicKey.findProgramAddressSync(
      [
        Buffer.from("collateral"),
        this.coordinator().toBuffer(),
        owner.toBuffer(),
        mint.toBuffer(),
      ],
      this.programId
    )[0];
  }

  hold(collateral: PublicKey, id: anchor.BN | number): PublicKey {
    return PublicKey.findProgramAddressSync(
      [
        Buffer.from("hold"),
        collateral.toBuffer(),
        new anchor.BN(id).toArrayLike(Buffer, "le", 8),
      ],
      this.programId
    )[0];
  }

  vaultAta(collateral: PublicKey, mint: PublicKey): PublicKey {
    return getAssociatedTokenAddressSync(mint, collateral, true);
  }

  async slot(): Promise<number> {
    return this.connection.getSlot("confirmed");
  }

  async vaultState(owner: PublicKey, mint: PublicKey) {
    const col = this.collateral(owner, mint);
    const acc = await (this.program.account as any).collateral.fetch(col);
    const deposited = BigInt(acc.deposited.toString());
    const held = BigInt(acc.held.toString());
    return {
      collateral: col.toBase58(),
      deposited: deposited.toString(),
      held: held.toString(),
      free: (deposited - held).toString(),
      settled: acc.settled.toString(),
      holdCount: acc.holdCount.toString(),
    };
  }

  async authorize(
    owner: PublicKey,
    mint: PublicKey,
    amount: anchor.BN,
    expirySlot: anchor.BN,
    merchantRef: number[]
  ): Promise<{ holdId: string; hold: string; signature: string }> {
    const col = this.collateral(owner, mint);
    const acc = await (this.program.account as any).collateral.fetch(col);
    const holdId: anchor.BN = acc.holdCount;
    const holdPda = this.hold(col, holdId);
    const signature = await this.program.methods
      .authorize(amount, expirySlot, merchantRef)
      .accounts({
        issuerAuthority: this.issuer.publicKey,
        coordinator: this.coordinator(),
        collateral: col,
        authHold: holdPda,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    return { holdId: holdId.toString(), hold: holdPda.toBase58(), signature };
  }

  async settle(
    owner: PublicKey,
    mint: PublicKey,
    holdId: anchor.BN,
    amount: anchor.BN,
    issuerTokenAccount: PublicKey
  ): Promise<string> {
    const col = this.collateral(owner, mint);
    return this.program.methods
      .settle(amount)
      .accounts({
        issuerAuthority: this.issuer.publicKey,
        coordinator: this.coordinator(),
        collateral: col,
        authHold: this.hold(col, holdId),
        mint,
        vaultTokenAccount: this.vaultAta(col, mint),
        issuerTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .rpc();
  }

  async release(
    owner: PublicKey,
    mint: PublicKey,
    holdId: anchor.BN
  ): Promise<string> {
    const col = this.collateral(owner, mint);
    return this.program.methods
      .release()
      .accounts({
        caller: this.issuer.publicKey,
        coordinator: this.coordinator(),
        issuerAuthority: this.issuer.publicKey,
        collateral: col,
        authHold: this.hold(col, holdId),
      })
      .rpc();
  }
}
