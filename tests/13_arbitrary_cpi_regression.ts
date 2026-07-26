import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Liquidator } from "../target/types/liquidator";
import { OracleRouter } from "../target/types/oracle_router";
import { PerpEngine } from "../target/types/perp_engine";
import {
  PublicKey,
  Keypair,
  SystemProgram,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import { assert } from "chai";

// ============================================================
// REGRESSION — arbitrary CPI: the callee program id must be bound
// ============================================================
// Guards the two fixes from docs/audit/2026-07-26-unaudited-programs-findings.md:
//
//   C-1 (CRITICAL) liquidator::liquidate  — `perp_engine_program` was an
//        unbound UncheckedAccount on a PERMISSIONLESS instruction that forwards
//        `liquidator_authority` (a registered perp_engine operator) as a CPI
//        *signer*. Signer privilege extends transitively through CPI
//        (agave program-runtime `prepare_next_instruction`), so any caller could
//        hand the engine operator role to a program of their choosing and then
//        drive `perp_engine::update_mark_price` at will.
//        Fix: `constraint = perp_engine_program.key() == config.perp_engine`.
//
//   H-1 (HIGH) oracle_router::push_price — same class. Anchor's typed `cpi::`
//        helper does NOT validate the program id (it builds the instruction with
//        `program_id: ctx.program.key()`), despite the old `/// CHECK: Validated
//        by CPI runtime` comment claiming otherwise.
//        Fix: `#[account(address = perp_engine::ID)]`.
//
// Each case is asserted TWICE, and both halves matter:
//   (a) foreign program id  -> MUST revert with our specific error;
//   (b) canonical program id -> MUST get past the guard (succeed, or fail with
//       some OTHER error). Without (b) these tests would still pass if the
//       constraint were deleted and something unrelated happened to revert.
//
// Ordering: runs after 03_oracle_router.ts and 06_liquidator.ts, which create
// the oracle config + feed and the liquidator config respectively.

/**
 * Anchor error name if present, else the raw string — for discriminating asserts.
 * Lower-cased because the committed artifacts disagree on casing: `idl/*.json`
 * carries `InvalidProgram`, `types/*.ts` carries `invalidProgram`, and which one
 * the client resolves depends on which was staged into `target/`.
 */
function errName(e: any): string {
  return (e?.error?.errorCode?.code ?? e?.toString() ?? "").toLowerCase();
}

describe("regression — arbitrary CPI program-id binding", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const liquidator = anchor.workspace.Liquidator as Program<Liquidator>;
  const oracle = anchor.workspace.OracleRouter as Program<OracleRouter>;
  const engine = anchor.workspace.PerpEngine as Program<PerpEngine>;

  const owner = (provider.wallet as anchor.Wallet).payer;

  // A real, executable program that is definitively NOT perp_engine. Using the
  // System Program (rather than a random keypair) proves the guard rejects on
  // *identity*, not merely on "not executable".
  const FOREIGN_PROGRAM = SystemProgram.programId;

  const marketIdBtc = Buffer.alloc(32);
  Buffer.from("BTC-USD").copy(marketIdBtc);

  // ---- engine PDAs ----
  const [engineConfigPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("engine_config")],
    engine.programId,
  );
  const [engineMarketPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("market"), marketIdBtc],
    engine.programId,
  );
  const engineOperatorPda = (op: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), op.toBuffer()],
      engine.programId,
    )[0];

  // ============================================================
  //  C-1 — liquidator::liquidate (permissionless)
  // ============================================================
  describe("C-1 liquidator::liquidate", () => {
    // The attacker is just some random funded keypair — that is the whole point
    // of this finding: `liquidate` is permissionless, no role required.
    const attacker = Keypair.generate();

    const [configPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("liquidator_config")],
      liquidator.programId,
    );
    const [liquidatorAuthorityPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("liquidator_authority")],
      liquidator.programId,
    );
    const [attackerStatsPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("keeper"), attacker.publicKey.toBuffer()],
      liquidator.programId,
    );
    // Position PDA is irrelevant to the guard (it fires during account
    // validation, before the handler) — any well-formed address works.
    const [somePositionPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("position"), marketIdBtc, attacker.publicKey.toBuffer()],
      engine.programId,
    );

    const liquidateWith = (programId: PublicKey) =>
      liquidator.methods
        .liquidate(Array.from(marketIdBtc))
        .accountsPartial({
          config: configPda,
          keeperStats: attackerStatsPda,
          liquidatorAuthority: liquidatorAuthorityPda,
          keeper: attacker.publicKey,
          perpEngineProgram: programId,
          engineConfig: engineConfigPda,
          engineMarket: engineMarketPda,
          enginePosition: somePositionPda,
          engineOperatorAccount: engineOperatorPda(liquidatorAuthorityPda),
          systemProgram: SystemProgram.programId,
        })
        .signers([attacker])
        .rpc();

    before(async () => {
      const sig = await provider.connection.requestAirdrop(
        attacker.publicKey,
        2 * LAMPORTS_PER_SOL,
      );
      await provider.connection.confirmTransaction(sig);
    });

    it("config.perp_engine is actually populated (the guard has something to bind to)", async () => {
      const cfg = await liquidator.account.liquidatorConfig.fetch(configPda);
      assert.equal(
        cfg.perpEngine.toBase58(),
        engine.programId.toBase58(),
        "liquidator config must point at the real perp_engine",
      );
    });

    it("rejects a foreign CPI target program (was: any caller could redirect the signed CPI)", async () => {
      let threw = false;
      try {
        await liquidateWith(FOREIGN_PROGRAM);
      } catch (e: any) {
        threw = true;
        assert.include(
          errName(e),
          "invalidprogram",
          `expected InvalidProgram, got: ${errName(e)}`,
        );
      }
      assert.isTrue(
        threw,
        "SECURITY REGRESSION: liquidate accepted a foreign perp_engine_program — " +
          "the signed liquidator_authority CPI can be redirected to an attacker program",
      );
    });

    it("still accepts the canonical perp_engine (guard is not rejecting everything)", async () => {
      // We do not care whether this liquidation succeeds — only that it gets
      // PAST the program-id guard. Anything but InvalidProgram proves that.
      try {
        await liquidateWith(engine.programId);
      } catch (e: any) {
        assert.notInclude(
          errName(e),
          "invalidprogram",
          "canonical perp_engine must not be rejected by the program-id guard",
        );
      }
    });
  });

  // ============================================================
  //  H-1 — oracle_router::push_price (operator-gated)
  // ============================================================
  describe("H-1 oracle_router::push_price", () => {
    // Own operator, so this file does not depend on 03's in-scope keypair.
    const oracleOperator = Keypair.generate();

    const [oracleConfigPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("oracle_config")],
      oracle.programId,
    );
    const [feedPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("feed"), marketIdBtc],
      oracle.programId,
    );
    const [oracleAuthorityPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("oracle_authority")],
      oracle.programId,
    );
    const [oracleOperatorPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("operator"), oracleOperator.publicKey.toBuffer()],
      oracle.programId,
    );

    const pushWith = async (programId: PublicKey) => {
      const ts = Math.floor(Date.now() / 1000);
      const feed = await oracle.account.feedConfig.fetch(feedPda);
      // Stay inside the circuit-breaker band so the canonical-path control is
      // not rejected for an unrelated reason.
      const price = feed.lastPrice.isZero()
        ? new anchor.BN(50_000_000_000)
        : feed.lastPrice;

      return oracle.methods
        .pushPrice(price, price, 0, new anchor.BN(ts - 1), new anchor.BN(50))
        .accountsPartial({
          oracleConfig: oracleConfigPda,
          feed: feedPda,
          operatorAccount: oracleOperatorPda,
          operator: oracleOperator.publicKey,
          oracleAuthority: oracleAuthorityPda,
          perpEngineProgram: programId,
          engineConfig: engineConfigPda,
          engineMarket: engineMarketPda,
          engineOperatorAccount: engineOperatorPda(oracleAuthorityPda),
        })
        .signers([oracleOperator])
        .rpc();
    };

    before(async () => {
      const sig = await provider.connection.requestAirdrop(
        oracleOperator.publicKey,
        2 * LAMPORTS_PER_SOL,
      );
      await provider.connection.confirmTransaction(sig);

      await oracle.methods
        .setOperator(oracleOperator.publicKey, true)
        .accountsPartial({
          oracleConfig: oracleConfigPda,
          operatorAccount: oracleOperatorPda,
          owner: owner.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    });

    it("rejects a foreign CPI target program (was: /// CHECK claimed the runtime validated it)", async () => {
      let threw = false;
      try {
        await pushWith(FOREIGN_PROGRAM);
      } catch (e: any) {
        threw = true;
        assert.include(
          errName(e),
          "invalidprogram",
          `expected InvalidProgram, got: ${errName(e)}`,
        );
      }
      assert.isTrue(
        threw,
        "SECURITY REGRESSION: push_price accepted a foreign perp_engine_program — " +
          "an oracle operator can escalate to the full engine operator surface",
      );
    });

    it("still accepts the canonical perp_engine (guard is not rejecting everything)", async () => {
      try {
        await pushWith(engine.programId);
      } catch (e: any) {
        assert.notInclude(
          errName(e),
          "invalidprogram",
          "canonical perp_engine must not be rejected by the program-id guard",
        );
      }
    });
  });
});
