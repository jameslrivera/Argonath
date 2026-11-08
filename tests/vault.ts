import * as anchor from "@coral-xyz/anchor";
import { Keypair, SystemProgram } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, getAccount } from "@solana/spl-token";
import { expect } from "chai";
import {
  Fixture,
  currentSlot,
  deposit,
  expectError,
  fund,
  holdPda,
  nextHoldPda,
  setupFixture,
  usdc,
  waitPastSlot,
} from "./helpers";

describe("vault core", () => {
  let f: Fixture;

  before(async () => {
    f = await setupFixture();
  });

  it("initializes coordinator with admins and threshold", async () => {
    const c = await f.program.account.coordinator.fetch(f.coordinator);
    expect(c.issuerAuthority.toBase58()).to.eq(f.issuer.publicKey.toBase58());
    expect(c.admins.length).to.eq(3);
    expect(c.threshold).to.eq(2);
    expect(c.nonce.toNumber()).to.eq(0);
    expect(c.paused).to.eq(false);
  });

  it("rejects threshold above admin count", async () => {
    const issuer2 = Keypair.generate();
    await fund(f.provider, issuer2.publicKey, 2);
    const [coord2] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("coordinator"), issuer2.publicKey.toBuffer()],
      f.program.programId
    );
    await expectError(
      f.program.methods
        .initCoordinator([Keypair.generate().publicKey], 2)
        .accounts({
          issuerAuthority: issuer2.publicKey,
          coordinator: coord2,
          systemProgram: SystemProgram.programId,
        })
        .signers([issuer2])
        .rpc(),
      "InvalidThreshold"
    );
  });

  it("rejects duplicate admins", async () => {
    const issuer3 = Keypair.generate();
    await fund(f.provider, issuer3.publicKey, 2);
    const [coord3] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("coordinator"), issuer3.publicKey.toBuffer()],
      f.program.programId
    );
    const dup = Keypair.generate().publicKey;
    await expectError(
      f.program.methods
        .initCoordinator([dup, dup], 1)
        .accounts({
          issuerAuthority: issuer3.publicKey,
          coordinator: coord3,
          systemProgram: SystemProgram.programId,
        })
        .signers([issuer3])
        .rpc(),
      "DuplicateAdmin"
    );
  });

  it("opens a collateral vault", async () => {
    const col = await f.program.account.collateral.fetch(f.collateral);
    expect(col.owner.toBase58()).to.eq(f.owner.publicKey.toBase58());
    expect(col.mint.toBase58()).to.eq(f.mint.toBase58());
    expect(col.deposited.toNumber()).to.eq(0);
    expect(col.held.toNumber()).to.eq(0);
  });

  it("deposits into the vault", async () => {
    await deposit(f, usdc(500));
    const col = await f.program.account.collateral.fetch(f.collateral);
    expect(col.deposited.toString()).to.eq(usdc(500).toString());
    const vault = await getAccount(f.provider.connection, f.vaultAta);
    expect(vault.amount.toString()).to.eq(usdc(500).toString());
  });

  it("rejects zero deposit", async () => {
    await expectError(deposit(f, new anchor.BN(0)), "ZeroAmount");
  });

  it("owner withdraws free collateral", async () => {
    await f.program.methods
      .withdrawFree(usdc(100))
      .accounts({
        owner: f.owner.publicKey,
        collateral: f.collateral,
        mint: f.mint,
        vaultTokenAccount: f.vaultAta,
        ownerTokenAccount: f.ownerAta,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([f.owner])
      .rpc();
    const col = await f.program.account.collateral.fetch(f.collateral);
    expect(col.deposited.toString()).to.eq(usdc(400).toString());
  });

  it("rejects withdrawal above free balance", async () => {
    await expectError(
      f.program.methods
        .withdrawFree(usdc(401))
        .accounts({
          owner: f.owner.publicKey,
          collateral: f.collateral,
          mint: f.mint,
          vaultTokenAccount: f.vaultAta,
          ownerTokenAccount: f.ownerAta,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([f.owner])
        .rpc(),
      "InsufficientFree"
    );
  });

  it("rejects withdrawal by non-owner", async () => {
    const stranger = Keypair.generate();
    await fund(f.provider, stranger.publicKey, 1);
    try {
      await f.program.methods
        .withdrawFree(usdc(1))
        .accounts({
          owner: stranger.publicKey,
          collateral: f.collateral,
          mint: f.mint,
          vaultTokenAccount: f.vaultAta,
          ownerTokenAccount: f.ownerAta,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([stranger])
        .rpc();
      throw new Error("should have failed");
    } catch (e: any) {
      expect(String(e)).to.not.include("should have failed");
    }
  });

  describe("authorization holds", () => {
    let hold0: anchor.web3.PublicKey;

    it("issuer places a hold", async () => {
      const slot = await currentSlot(f);
      hold0 = holdPda(f.program, f.collateral, 0);
      await f.program.methods
        .authorize(usdc(150), new anchor.BN(slot + 1000), Array(32).fill(1))
        .accounts({
          issuerAuthority: f.issuer.publicKey,
          coordinator: f.coordinator,
          collateral: f.collateral,
          authHold: hold0,
          systemProgram: SystemProgram.programId,
        })
        .signers([f.issuer])
        .rpc();
      const col = await f.program.account.collateral.fetch(f.collateral);
      expect(col.held.toString()).to.eq(usdc(150).toString());
      expect(col.holdCount.toNumber()).to.eq(1);
      const h = await f.program.account.authHold.fetch(hold0);
      expect(h.amount.toString()).to.eq(usdc(150).toString());
    });

    it("hold reduces withdrawable balance", async () => {
      await expectError(
        f.program.methods
          .withdrawFree(usdc(300))
          .accounts({
            owner: f.owner.publicKey,
            collateral: f.collateral,
            mint: f.mint,
            vaultTokenAccount: f.vaultAta,
            ownerTokenAccount: f.ownerAta,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([f.owner])
          .rpc(),
        "InsufficientFree"
      );
    });

    it("rejects hold above free balance", async () => {
      const slot = await currentSlot(f);
      await expectError(
        f.program.methods
          .authorize(usdc(251), new anchor.BN(slot + 1000), Array(32).fill(2))
          .accounts({
            issuerAuthority: f.issuer.publicKey,
            coordinator: f.coordinator,
            collateral: f.collateral,
            authHold: holdPda(f.program, f.collateral, 1),
            systemProgram: SystemProgram.programId,
          })
          .signers([f.issuer])
          .rpc(),
        "InsufficientFree"
      );
    });

    it("rejects hold with past expiry", async () => {
      await expectError(
        f.program.methods
          .authorize(usdc(1), new anchor.BN(1), Array(32).fill(3))
          .accounts({
            issuerAuthority: f.issuer.publicKey,
            coordinator: f.coordinator,
            collateral: f.collateral,
            authHold: holdPda(f.program, f.collateral, 1),
            systemProgram: SystemProgram.programId,
          })
          .signers([f.issuer])
          .rpc(),
        "BadExpiry"
      );
    });

    it("rejects hold from non-issuer", async () => {
      const slot = await currentSlot(f);
      try {
        await f.program.methods
          .authorize(usdc(1), new anchor.BN(slot + 100), Array(32).fill(4))
          .accounts({
            issuerAuthority: f.owner.publicKey,
            coordinator: f.coordinator,
            collateral: f.collateral,
            authHold: holdPda(f.program, f.collateral, 1),
            systemProgram: SystemProgram.programId,
          })
          .signers([f.owner])
          .rpc();
        throw new Error("should have failed");
      } catch (e: any) {
        expect(String(e)).to.not.include("should have failed");
      }
    });

    it("issuer settles part of the hold and remainder is freed", async () => {
      await f.program.methods
        .settle(usdc(120))
        .accounts({
          issuerAuthority: f.issuer.publicKey,
          coordinator: f.coordinator,
          collateral: f.collateral,
          authHold: hold0,
          mint: f.mint,
          vaultTokenAccount: f.vaultAta,
          issuerTokenAccount: f.issuerAta,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([f.issuer])
        .rpc();
      const col = await f.program.account.collateral.fetch(f.collateral);
      expect(col.deposited.toString()).to.eq(usdc(280).toString());
      expect(col.held.toNumber()).to.eq(0);
      expect(col.settled.toString()).to.eq(usdc(120).toString());
      const issuerBal = await getAccount(f.provider.connection, f.issuerAta);
      expect(issuerBal.amount.toString()).to.eq(usdc(120).toString());
      const info = await f.provider.connection.getAccountInfo(hold0);
      expect(info).to.eq(null);
    });

    it("rejects settling more than the hold", async () => {
      const slot = await currentSlot(f);
      const hold1 = holdPda(f.program, f.collateral, 1);
      await f.program.methods
        .authorize(usdc(50), new anchor.BN(slot + 1000), Array(32).fill(5))
        .accounts({
          issuerAuthority: f.issuer.publicKey,
          coordinator: f.coordinator,
          collateral: f.collateral,
          authHold: hold1,
          systemProgram: SystemProgram.programId,
        })
        .signers([f.issuer])
        .rpc();
      await expectError(
        f.program.methods
          .settle(usdc(51))
          .accounts({
            issuerAuthority: f.issuer.publicKey,
            coordinator: f.coordinator,
            collateral: f.collateral,
            authHold: hold1,
            mint: f.mint,
            vaultTokenAccount: f.vaultAta,
            issuerTokenAccount: f.issuerAta,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([f.issuer])
          .rpc(),
        "SettleExceedsHold"
      );
    });

    it("stranger cannot release an unexpired hold", async () => {
      const stranger = Keypair.generate();
      await fund(f.provider, stranger.publicKey, 1);
      await expectError(
        f.program.methods
          .release()
          .accounts({
            caller: stranger.publicKey,
            coordinator: f.coordinator,
            issuerAuthority: f.issuer.publicKey,
            collateral: f.collateral,
            authHold: holdPda(f.program, f.collateral, 1),
          })
          .signers([stranger])
          .rpc(),
        "HoldNotExpired"
      );
    });

    it("issuer releases a hold at any time", async () => {
      await f.program.methods
        .release()
        .accounts({
          caller: f.issuer.publicKey,
          coordinator: f.coordinator,
          issuerAuthority: f.issuer.publicKey,
          collateral: f.collateral,
          authHold: holdPda(f.program, f.collateral, 1),
        })
        .signers([f.issuer])
        .rpc();
      const col = await f.program.account.collateral.fetch(f.collateral);
      expect(col.held.toNumber()).to.eq(0);
    });

    it("anyone can release an expired hold", async () => {
      const slot = await currentSlot(f);
      const expiry = slot + 6;
      const hold2 = await nextHoldPda(f);
      await f.program.methods
        .authorize(usdc(10), new anchor.BN(expiry), Array(32).fill(6))
        .accounts({
          issuerAuthority: f.issuer.publicKey,
          coordinator: f.coordinator,
          collateral: f.collateral,
          authHold: hold2,
          systemProgram: SystemProgram.programId,
        })
        .signers([f.issuer])
        .rpc();
      await waitPastSlot(f, expiry);
      const stranger = Keypair.generate();
      await fund(f.provider, stranger.publicKey, 1);
      await f.program.methods
        .release()
        .accounts({
          caller: stranger.publicKey,
          coordinator: f.coordinator,
          issuerAuthority: f.issuer.publicKey,
          collateral: f.collateral,
          authHold: hold2,
        })
        .signers([stranger])
        .rpc();
      const col = await f.program.account.collateral.fetch(f.collateral);
      expect(col.held.toNumber()).to.eq(0);
    });

    it("cannot settle an expired hold", async () => {
      const slot = await currentSlot(f);
      const expiry = slot + 6;
      const hold3 = await nextHoldPda(f);
      await f.program.methods
        .authorize(usdc(10), new anchor.BN(expiry), Array(32).fill(7))
        .accounts({
          issuerAuthority: f.issuer.publicKey,
          coordinator: f.coordinator,
          collateral: f.collateral,
          authHold: hold3,
          systemProgram: SystemProgram.programId,
        })
        .signers([f.issuer])
        .rpc();
      await waitPastSlot(f, expiry);
      await expectError(
        f.program.methods
          .settle(usdc(10))
          .accounts({
            issuerAuthority: f.issuer.publicKey,
            coordinator: f.coordinator,
            collateral: f.collateral,
            authHold: hold3,
            mint: f.mint,
            vaultTokenAccount: f.vaultAta,
            issuerTokenAccount: f.issuerAta,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([f.issuer])
          .rpc(),
        "HoldExpired"
      );
      await f.program.methods
        .release()
        .accounts({
          caller: f.issuer.publicKey,
          coordinator: f.coordinator,
          issuerAuthority: f.issuer.publicKey,
          collateral: f.collateral,
          authHold: hold3,
        })
        .signers([f.issuer])
        .rpc();
    });
  });

  describe("pause", () => {
    it("issuer pauses and authorize is blocked", async () => {
      await f.program.methods
        .setPaused(true)
        .accounts({
          issuerAuthority: f.issuer.publicKey,
          coordinator: f.coordinator,
        })
        .signers([f.issuer])
        .rpc();
      const slot = await currentSlot(f);
      await expectError(
        f.program.methods
          .authorize(usdc(1), new anchor.BN(slot + 100), Array(32).fill(8))
          .accounts({
            issuerAuthority: f.issuer.publicKey,
            coordinator: f.coordinator,
            collateral: f.collateral,
            authHold: await nextHoldPda(f),
            systemProgram: SystemProgram.programId,
          })
          .signers([f.issuer])
          .rpc(),
        "Paused"
      );
    });

    it("owner can still withdraw while paused", async () => {
      await f.program.methods
        .withdrawFree(usdc(10))
        .accounts({
          owner: f.owner.publicKey,
          collateral: f.collateral,
          mint: f.mint,
          vaultTokenAccount: f.vaultAta,
          ownerTokenAccount: f.ownerAta,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([f.owner])
        .rpc();
      const col = await f.program.account.collateral.fetch(f.collateral);
      expect(col.deposited.toString()).to.eq(usdc(270).toString());
    });

    it("unpauses", async () => {
      await f.program.methods
        .setPaused(false)
        .accounts({
          issuerAuthority: f.issuer.publicKey,
          coordinator: f.coordinator,
        })
        .signers([f.issuer])
        .rpc();
      const c = await f.program.account.coordinator.fetch(f.coordinator);
      expect(c.paused).to.eq(false);
    });
  });
});
