import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  createAssociatedTokenAccountIdempotent,
  createMint,
  getAssociatedTokenAddressSync,
  mintTo,
} from "@solana/spl-token";
import { Collateral } from "../target/types/collateral";

export const DECIMALS = 6;

export function usdc(n: number): anchor.BN {
  return new anchor.BN(Math.round(n * 10 ** DECIMALS));
}

export async function airdrop(
  provider: anchor.AnchorProvider,
  to: PublicKey,
  sol = 10
): Promise<void> {
  const sig = await provider.connection.requestAirdrop(
    to,
    sol * LAMPORTS_PER_SOL
  );
  await provider.connection.confirmTransaction(sig, "confirmed");
}

export async function fund(
  provider: anchor.AnchorProvider,
  to: PublicKey,
  sol = 10
): Promise<void> {
  const tx = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: provider.wallet.publicKey,
      toPubkey: to,
      lamports: sol * LAMPORTS_PER_SOL,
    })
  );
  await provider.sendAndConfirm(tx);
}

export function coordinatorPda(
  program: Program<Collateral>,
  issuer: PublicKey
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("coordinator"), issuer.toBuffer()],
    program.programId
  )[0];
}

export function collateralPda(
  program: Program<Collateral>,
  coordinator: PublicKey,
  owner: PublicKey,
  mint: PublicKey
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("collateral"),
      coordinator.toBuffer(),
      owner.toBuffer(),
      mint.toBuffer(),
    ],
    program.programId
  )[0];
}

export function holdPda(
  program: Program<Collateral>,
  collateral: PublicKey,
  id: anchor.BN | number
): PublicKey {
  const idBn = new anchor.BN(id);
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("hold"),
      collateral.toBuffer(),
      idBn.toArrayLike(Buffer, "le", 8),
    ],
    program.programId
  )[0];
}

export interface Fixture {
  provider: anchor.AnchorProvider;
  program: Program<Collateral>;
  issuer: Keypair;
  owner: Keypair;
  admins: Keypair[];
  mint: PublicKey;
  coordinator: PublicKey;
  collateral: PublicKey;
  vaultAta: PublicKey;
  ownerAta: PublicKey;
  issuerAta: PublicKey;
}

export async function setupFixture(
  threshold = 2,
  adminCount = 3
): Promise<Fixture> {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.Collateral as Program<Collateral>;

  const issuer = Keypair.generate();
  const owner = Keypair.generate();
  const admins = Array.from({ length: adminCount }, () => Keypair.generate());
  await fund(provider, issuer.publicKey);
  await fund(provider, owner.publicKey);

  const mint = await createMint(
    provider.connection,
    issuer,
    issuer.publicKey,
    null,
    DECIMALS
  );

  const coordinator = coordinatorPda(program, issuer.publicKey);
  await program.methods
    .initCoordinator(
      admins.map((a) => a.publicKey),
      threshold
    )
    .accounts({
      issuerAuthority: issuer.publicKey,
      coordinator,
      systemProgram: SystemProgram.programId,
    })
    .signers([issuer])
    .rpc();

  const collateral = collateralPda(
    program,
    coordinator,
    owner.publicKey,
    mint
  );
  const vaultAta = getAssociatedTokenAddressSync(mint, collateral, true);
  await program.methods
    .openCollateral()
    .accounts({
      owner: owner.publicKey,
      coordinator,
      mint,
      collateral,
      vaultTokenAccount: vaultAta,
      tokenProgram: TOKEN_PROGRAM_ID,
      associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      systemProgram: SystemProgram.programId,
    })
    .signers([owner])
    .rpc();

  const ownerAta = await createAssociatedTokenAccountIdempotent(
    provider.connection,
    owner,
    mint,
    owner.publicKey
  );
  const issuerAta = await createAssociatedTokenAccountIdempotent(
    provider.connection,
    issuer,
    mint,
    issuer.publicKey
  );
  await mintTo(
    provider.connection,
    issuer,
    mint,
    ownerAta,
    issuer,
    usdc(1_000).toNumber()
  );

  return {
    provider,
    program,
    issuer,
    owner,
    admins,
    mint,
    coordinator,
    collateral,
    vaultAta,
    ownerAta,
    issuerAta,
  };
}

export async function deposit(f: Fixture, amount: anchor.BN): Promise<void> {
  await f.program.methods
    .deposit(amount)
    .accounts({
      depositor: f.owner.publicKey,
      collateral: f.collateral,
      mint: f.mint,
      vaultTokenAccount: f.vaultAta,
      depositorTokenAccount: f.ownerAta,
      tokenProgram: TOKEN_PROGRAM_ID,
    })
    .signers([f.owner])
    .rpc();
}

export async function currentSlot(f: Fixture): Promise<number> {
  return f.provider.connection.getSlot("confirmed");
}

export async function expectError(
  p: Promise<unknown>,
  code: string
): Promise<void> {
  try {
    await p;
  } catch (e: any) {
    const got =
      e?.error?.errorCode?.code ?? e?.errorCode?.code ?? String(e?.message);
    if (got !== code && !String(e).includes(code)) {
      throw new Error(`expected ${code}, got ${got}: ${e}`);
    }
    return;
  }
  throw new Error(`expected error ${code} but call succeeded`);
}

export async function nextHoldPda(f: Fixture): Promise<PublicKey> {
  const col = await f.program.account.collateral.fetch(f.collateral);
  return holdPda(f.program, f.collateral, col.holdCount);
}

export async function waitPastSlot(f: Fixture, slot: number): Promise<void> {
  while ((await currentSlot(f)) <= slot) {
    await new Promise((r) => setTimeout(r, 400));
  }
}
