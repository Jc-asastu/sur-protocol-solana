# SUR Protocol (Solana) — Findings: previously un-audited programs

**Date:** 2026-07-26
**Commit audited:** `4c1cb9e` (identical to the 2026-07-21 audited tree — no upstream code change since)
**Scope:** the 5 programs the 2026-07-21 repo-wide audit did **not** cover:
`oracle_router`, `insurance_fund`, `auto_deleveraging`, `liquidator`, `sur_timelock` (~3.1k LOC).
**Method:** Trail-of-Bits 6-pattern Solana scan + manual CPI/authority review, with the
severity-deciding runtime semantics verified against primary sources (see §3).

---

## 0. Summary

| ID | Severity | Program | One-line |
|----|----------|---------|----------|
| **C-1** | **CRITICAL** | `liquidator` | Permissionless arbitrary CPI: `perp_engine_program` is unbound, and the CPI is signed by `liquidator_authority`, a registered perp_engine **operator**. Any caller gains the engine operator role → arbitrary mark price on any market. |
| **H-1** | **HIGH** | `oracle_router` | Same class in `push_price` (`perp_engine_program` unbound; Anchor's typed `cpi::` does **not** validate the program id). Operator-gated, so it is a privilege-escalation rather than an open door. |
| **A-1** | *assumption correction* | `a2a_darkpool` | The 2026-07-21 audit bounded its arbitrary-CPI MEDIUM with "single-hop PDA-sig non-propagation". **That premise is false** (§3). Those rows need re-rating. |

The root cause of C-1 and H-1 is a *missed* constraint, not a design posture — the sibling
programs in the same repo, written in the same style, **do** apply it:

| Program | binds the CPI program id? | who can call |
|---|---|---|
| `insurance_fund/reward.rs:53` | ✅ `constraint = perp_vault_program.key() == config.vault` | operator |
| `auto_deleveraging/execute_adl.rs:68` | ✅ `constraint = perp_engine_program.key() == config.perp_engine` | operator |
| `oracle_router/push_price.rs:56` | ❌ none | operator |
| `liquidator/liquidate.rs:74` | ❌ none | **anyone** |

---

## 1. [CRITICAL] C-1 — `liquidator::liquidate`: permissionless arbitrary CPI yields the perp_engine operator role

**Location:** `programs/liquidator/src/instructions/liquidate.rs:74`, `:66`, `:70`;
`programs/liquidator/src/instructions/cpi_util.rs:67`, `:85`, `:102`

### The defect

`Liquidate` declares the callee program as a free account:

```rust
// liquidate.rs:73-74
/// CHECK: perp_engine program id.
pub perp_engine_program: UncheckedAccount<'info>,
```

`LiquidatorConfig` **has** the field to check it against — `perp_engine: Pubkey` (`state.rs:11`),
populated at `initialize` (`admin.rs:38`) — but **it is written and never read anywhere in the
program**. No `constraint`, no `require_keys_eq!`.

The instruction is then built with that attacker-chosen key and signed by the authority PDA:

```rust
// cpi_util.rs:62-68
let mut accounts = vec![
    ...
    AccountMeta::new_readonly(liquidator_authority.key(), true), // signer
];
// cpi_util.rs:84-88
let ix = Instruction { program_id: perp_engine_program.key(), accounts, data };
// cpi_util.rs:102
invoke_signed(&ix, &infos, &[auth_seeds])
```

And the entry point is **permissionless** — there is no operator gate, only a pause check:

```rust
// liquidate.rs:68-70
/// Anyone can call — keeper claims signature for stats.
#[account(mut)]
pub keeper: Signer<'info>,
```

### Why it is CRITICAL and not "an unbound account"

Three facts compose:

1. **The signature reaches the attacker's program.** `liquidator_authority` is passed with
   `is_signer = true` and granted by `invoke_signed`.
2. **The signature keeps working one hop deeper.** Verified against the Agave runtime — see §3.
   The attacker's program can re-present `liquidator_authority` as a signer in its own CPI.
3. **That PDA is a privileged role on the real engine.** Not merely a test artifact:
   `scripts/devnet-state.json:41` records `"engine.set_operator.liquidator_authority": "ok"`.

`perp_engine::update_mark_price` is gated by **nothing but** that role:

```rust
// perp_engine/src/instructions/update_mark_price.rs:31-39
constraint = operator_account.operator == operator.key(),
constraint = operator_account.authorized @ EngineError::NotOperator,
...
pub operator: Signer<'info>,
```

…and its handler writes the price unconditionally: `m.mark_price = new_mark_price;`.

### Attack

1. Attacker deploys a trivial forwarding program `E`.
2. Attacker calls `liquidator.liquidate(market_id)` — permissionless — passing
   `perp_engine_program = E`, and passing the **real** engine `EngineConfig`, the target `Market`
   (already declared `mut` at `liquidate.rs:78`, so writable), and the real `Operator` PDA for
   `liquidator_authority`.
3. Liquidator `invoke_signed`s `E`. `E`'s context now holds `liquidator_authority` as signer and
   `Market` as writable.
4. `E` CPIs the **real** `perp_engine::update_mark_price(new_mark_price, new_index_price)`,
   presenting `liquidator_authority` as the operator signer. Privilege check passes via the
   `caller_instruction_account.is_signer()` branch (§3).
5. Mark price of any active market is now attacker-set.

Cost to the attacker: one program deployment plus `keeper_stats` rent. No key, no role, no
compromise of any operator.

**Impact:** arbitrary mark price on the perp engine is total control of the venue —
forge unrealized PnL, force or prevent liquidations, and extract against the pools. The whole
engine-operator surface (`open_position`, `close_position`, `reduce_position`,
`liquidate_position`) is likewise reachable.

### Fix

```rust
#[account(
    constraint = perp_engine_program.key() == config.perp_engine @ LiquidatorError::InvalidProgram
)]
pub perp_engine_program: UncheckedAccount<'info>,
```

Byte-for-byte the constraint `auto_deleveraging/execute_adl.rs:68` already uses. Add
`InvalidProgram` to `LiquidatorError`.

**Defense-in-depth (recommended alongside):** scope the engine `Operator` record so
`liquidator_authority` may only invoke `liquidate_position`, not the full operator surface. Today
one unbound account exposes every operator-gated instruction at once.

---

## 2. [HIGH] H-1 — `oracle_router::push_price`: unbound callee program on the typed CPI

**Location:** `programs/oracle_router/src/instructions/push_price.rs:56`, `:160-165`

```rust
/// CHECK: perp_engine program. Validated by CPI runtime.
pub perp_engine_program: UncheckedAccount<'info>,
```

The `CHECK` comment states the runtime validates it. **It does not.** Anchor's generated CPI
builds `Instruction { program_id: ctx.program.key(), .. }` with **no** comparison against the
callee's declared `crate::ID` (§3) — using `CpiContext::new_with_signer` over an `AccountInfo`
performs no program-id check. Only the `Program<'info, T>` account type does that.

So `push_price` hands `oracle_authority` — also a registered engine operator
(`devnet-state.json:46`) — as a signer to an arbitrary program, with the same escalation as C-1.

**Why HIGH and not CRITICAL:** `push_price` is gated by
`operator_account.authorized` (`push_price.rs:36-44`), so the caller must already hold an
oracle-router operator key. It converts a *narrow* role (push a price within staleness,
confidence, deviation and circuit-breaker bounds) into the *entire* engine operator surface —
bypassing every safety control the program's own 90 lines of validation exist to enforce,
including the circuit breaker. It is a privilege-escalation and a control bypass, not an open door.

### Fix

```rust
#[account(constraint = perp_engine_program.key() == oracle_config.perp_engine @ OracleError::InvalidProgram)]
pub perp_engine_program: UncheckedAccount<'info>,
```

`OracleConfig` does not currently carry the engine program id — add the field, set it at
`initialize`, mirroring `ADLConfig::perp_engine`. Also correct the misleading `/// CHECK:` comment.

---

## 3. Runtime semantics — the premise the 2026-07-21 audit got wrong

The prior audit rated `a2a_darkpool`'s arbitrary-CPI issues MEDIUM, explicitly bounded as
*"bounded by single-hop PDA-sig non-propagation"* and *"a PDA signature cannot be re-signed one hop
deeper"* (`2026-07-21-AUDIT-SUMMARY.md:55`, `:113-115`).

**That is not how the runtime behaves.** From Agave `program-runtime/src/invoke_context.rs`
(`prepare_next_instruction`, v3.1.8):

```rust
if instruction_account.is_signer()
    && !(caller_instruction_account.is_signer() || signers.contains(account_key))
{
    return Err(InstructionError::PrivilegeEscalation);
}
```

The `signers` set (PDA seeds) is only the **second** disjunct. The first —
`caller_instruction_account.is_signer()` — is satisfied for any program that received the account
as a signer. When the malicious program makes its own CPI it *is* the caller, and in its context
the PDA is already a signer. The privilege therefore **propagates transitively**, limited only by
max CPI depth (4 nested, 5 total).

Corroborated by Asymmetric Research's CPI security write-up: *"any account marked as a signer in
the current execution context is passed along with that status to the next one"*, and
*"combining the signer privileges with an Arbitrary CPI can have devastating consequences"*.

**Consequence:** the mitigating premise behind the `a2a_darkpool` MEDIUM rows (and the
"bounded today" language in Chain C) does not hold. Those rows should be re-rated on the corrected
model. Not re-examined in this pass — flagged.

**Sources**
- Agave runtime: `https://github.com/anza-xyz/agave/blob/v3.1.8/program-runtime/src/invoke_context.rs#L395-L399`
- Solana docs, CPI execution & privileges: `https://solana.com/docs/core/cpi/cpi-execution`
- Anchor v0.31.1 CPI codegen: `lang/syn/src/codegen/program/cpi.rs`
- Asymmetric Research, *Invocation Security: Navigating Vulnerabilities in Solana CPIs*

---

## 3b. [CRITICAL] D-1 — `a2a_darkpool::accept_and_settle`: permissionless drain of any depositor

Found by re-examining the rows §3 invalidated. **Strictly worse than C-1**: no role is required and
the victim is arbitrary. Every link below was read in the source, not inferred.

**Location:** `accept_and_settle.rs:107`, `:133`, `:137`, `:450`, `:605`, `:611-612`, `:656`, `:662`

### Two independent defects that compose

**D-1a — the CPI target programs are unbound.** `perp_engine_program` (`:107`) and
`perp_vault_program` (`:137`) are bare `UncheckedAccount`s. `DarkPoolConfig` *does* hold
`perp_engine` and `perp_vault`, and the handler uses them to derive PDAs at `:182`, `:234-251` —
but never to constrain the program ids themselves. The CPIs then build
`program_id: perp_vault_program.key()` (`:656`) and pass `darkpool_authority` as a **signer**
(`:605`, `:662`).

**D-1b — `engine_pool_balance` is never validated at all.** Gate 0b (`:232-256`) binds
`buyer_balance`, `seller_balance`, `fee_recipient_balance` and `engine_market`. `engine_pool_balance`
is **absent from it**. Grep confirms the account appears only at its declaration (`:133`) and then
directly in CPI account lists as **writable** (`:450`, `:612`) — it is checked nowhere. The caller
therefore chooses it freely.

### Preconditions — all confirmed, none privileged

| Precondition | Evidence |
|---|---|
| Anyone can post an intent | `post_intent.rs:49` — `agent: Signer` |
| Anyone can post a response | `post_response.rs:53` — `responder: Signer` |
| The intent creator calls settle | `accept_and_settle.rs:64,93` — the code's own comment at `:230` calls it "a permissionless intent_creator" |
| `darkpool_authority` is an operator on **both** programs | `scripts/devnet-state.json:40` (`vault.set_operator.a2a_darkpool_authority: ok`) and `:45` (engine) |
| Signer privilege survives the extra hop | §3 — verified against Agave `prepare_next_instruction` |
| An operator may move **any** balance | `perp_vault/internal_transfer.rs:40-52` — `from_balance` seeds bind to `from_balance.trader`, the account's *own* stored field; the only gate is `operator_account.authorized`. This is the 2026-07-21 `perp_vault` HIGH-1, still open. |

### Attack

1. Attacker posts an intent from wallet A and a response from wallet B (both permissionless; two
   wallets also sidestep the self-trade check).
2. Calls `accept_and_settle` signing as A, passing the genuine `engine_market` and its own
   `buyer_balance`/`seller_balance` so Gate 0b is satisfied, plus:
   - `engine_pool_balance` = **any victim's `AccountBalance` PDA** (unvalidated),
   - `perp_engine_program` = an attacker-deployed program `E`.
3. The darkpool `invoke_signed`s `E`, handing it `darkpool_authority` as a signer, the victim's
   balance as **writable** (`:612`), and the attacker's `trader_balance` as **writable** (`:611`).
4. `E` CPIs the **real** `perp_vault.internal_transfer(amount)` with `from` = victim,
   `to` = attacker, `operator` = `darkpool_authority`.
5. `internal_transfer` sees an authorized operator and a well-formed `from_balance`. It transfers.

**Impact:** permissionless theft of any depositor's vault balance, capped per transaction only by
`max_operator_transfer_per_tx` (if configured non-zero) and repeatable in a loop. The margin pool
(`engine_authority`'s balance) is drainable the same way — it is just another `AccountBalance` PDA.

### Fix

Both, independently:

```rust
// D-1a — mirror the constraint the sibling programs already use.
#[account(constraint = perp_engine_program.key() == config.perp_engine @ DarkPoolError::InvalidAccount)]
pub perp_engine_program: UncheckedAccount<'info>,
#[account(constraint = perp_vault_program.key() == config.perp_vault @ DarkPoolError::InvalidAccount)]
pub perp_vault_program: UncheckedAccount<'info>,
```

```rust
// D-1b — bind the pool inside Gate 0b, exactly like the other balances.
let (exp_pool, _) = Pubkey::find_program_address(
    &[b"balance", ctx.accounts.engine_authority.key().as_ref()], &pv);
require!(ctx.accounts.engine_pool_balance.key() == exp_pool, DarkPoolError::InvalidAccount);
```

D-1a alone closes the chain; D-1b is independently necessary, since an unvalidated writable account
forwarded into any CPI is a standing hazard. `engine_authority` and `engine_vault_operator`
(`:128`, `:130`) are unbound on the same struct and should be bound in the same pass.

**Root-cause note:** this is the third instance of one defect class in one day (`liquidator`,
`oracle_router`, `a2a_darkpool`). The class is *"an account whose canonical value is already sitting
in `config`, forwarded into a signed CPI without being compared to it."* Worth a lint or a review
checklist item rather than three point fixes.

**Status: ✅ Fixed 2026-07-26.** Both constraints applied; `engine_authority` and
`engine_vault_operator` bound in the same pass. Compile-verified. See §6 for the amplifier fix that
independently breaks step 5 of the chain.

**Regression test: NOT written.** Unlike C-1/H-1, the guards here sit behind `intent`, `response`
and both reputation PDAs, so a negative test needs the full `tests/04_a2a_darkpool.ts` fixture
(posted intent + matching response + initialised reputations). Authoring that blind, against a
suite that has never run, would produce a test whose failure mode is indistinguishable from a
fixture mistake. It should be added inside `04_a2a_darkpool.ts`, after its first successful settle,
asserting exactly:

1. `perp_engine_program` = any other program id → reverts `InvalidAccount`.
2. `perp_vault_program` = any other program id → reverts `InvalidAccount`.
3. `engine_pool_balance` = a balance PDA that is not `engine_authority`'s → reverts `InvalidAccount`.
4. The unmodified canonical call still settles — otherwise 1–3 pass vacuously.

---

## 6. [HIGH] perp_vault HIGH-1 — operator scoping (the amplifier)

**Closed 2026-07-26.** Open since the 2026-07-21 audit, where it was deferred pending the
still-unmade trust-model decision.

This is the finding that turns the others into money. `internal_transfer` gated on
`operator_account.authorized` — which answers *whether* a key may move funds and never *whose*. Any
one operator key, or any program able to borrow one operator's signature for a single CPI hop, could
move value between two arbitrary third parties. Every chain in this document ends at that primitive.

**Fix — `perp_vault/internal_transfer.rs:71-94`.** An operator-initiated transfer must satisfy:

```
from.trader == operator  ||  to.trader == operator  ||  to.trader == operator.allowed_sink
```

The invariant is *"the operator must be a party to the transfer, or it must be a fee leg into a
sink the owner granted explicitly."* An attacker who chooses both sides satisfies none of the three.

**Why this shape.** Every settlement flow in the protocol already puts the calling authority on one
side — the engine locks margin *into* `engine_pool` and pays out *from* it; the insurance fund pays
*from* its own balance; a trading vault moves against its own balance. The sole exception is a
protocol fee leg (`a2a_darkpool` and `order_settlement` move `trader -> fee_recipient` with their
authority on neither side), which is what `allowed_sink` exists to permit — and nothing else.

**Delivery choices worth knowing:**

- `allowed_sink` is granted by a **new, separate** `set_operator_sink` instruction rather than a new
  argument on `set_operator`. That keeps all ~30 existing `setOperator` call sites compiling
  untouched, and makes granting the privilege an explicit, auditable act rather than a defaulted
  argument. It cannot create the operator PDA, so a sink can never be granted to an unregistered key.
- The guard is placed **after** the `SameAccount` check, so `tests/12_vault_alias_mint_red.ts`
  still observes `SameAccount` and is unaffected.
- `OperatorNotParty` is appended to the error enum (code `6017`); no existing code shifts.

### ⚠️ Breaking changes this fix carries

1. **`Operator` grows by 32 bytes.** Existing deployed `Operator` PDAs are undersized and will fail
   to deserialize. **Devnet must be re-initialised** (`scripts/devnet-init.ts`), not just redeployed.
2. **`a2a_darkpool` and `order_settlement` fee legs now require a sink.** `devnet-init.ts` grants
   both (`vault.set_operator_sink`, wired to the same `feeRecipient` those programs are initialised
   with). If that value ever changes, update both places or the fee legs start failing with
   `OperatorNotParty`.
3. **`tests/01_perp_vault.ts` asserted the vulnerability as correct behaviour** — "operator does
   internalTransfer of 10 USDC trader1 -> trader2", with the operator on neither side. It has been
   split into a negative case (the unscoped move must revert) plus an explicit sink grant before the
   original transfer, so downstream balances are unchanged. This was the only test that broke.

### Verification performed

| Check | Result |
|-------|--------|
| `cargo check --workspace` (forced rebuild) | ✅ zero errors |
| `tsc --noEmit` on `tests/13`, `scripts/devnet-init.ts` | ✅ clean |
| `tsc --noEmit` on modified `tests/01_perp_vault.ts` | ✅ 6 pre-existing `.accounts()` errors vs **7** in the unmodified original — no new ones |
| `idl/`, `types/`, `clients/web/idls/` for `perp_vault` | ✅ patched + cross-checked; see below |

**Incidental fix.** Cross-checking the artifacts surfaced pre-existing drift unrelated to this work:
`clients/web/idls/perp_vault.json` was **missing the `SameAccount` error** added by the 2026-07-21
CRITICAL-1 fix, so the web client had been mis-numbering vault errors since then. Its `errors` array
is now resynchronised to the canonical IDL.

**Still not runtime-verified.** As with C-1/H-1, `anchor test` cannot run here — see §5.

---

## 3c. Second pass — sweep completed, two further findings

### The defect class is now fully swept

Every CPI target program id in the repo was checked against its `config` counterpart. The three
instances in §1/§2/§3b were the only ones:

| Program | Binds the callee program id? |
|---|---|
| `order_settlement` | ✅ `settle.rs:71`, `:104` |
| `collateral_manager` | ✅ `deposit.rs:67`, `withdraw.rs:70` |
| `insurance_fund` | ✅ `reward.rs:53` |
| `auto_deleveraging` | ✅ `execute_adl.rs:68` |
| `trading_vault` | ✅ its own ids; the `perp_vault_program` it forwards at `manager_trade.rs:68` is unbound **but validated by the callee** — see below |
| `perp_engine` | ✅ all five vault-CPI paths: `open_position.rs:192`, `close_position.rs:132`/`:172`, `liquidate_position.rs:182`/`:238`, `reduce_position.rs:220` |

**Rejected suspicion.** `trading_vault/manager_trade.rs:68` forwards `perp_vault_program` with no
constraint, which looks like the same bug one hop deeper. It is not exploitable: `perp_engine`
re-derives and enforces `vault_program.key() == cfg.perp_vault` in every path that consumes it,
alongside Gate 0a and `assert_engine_authority`. Recorded so the next reviewer does not re-chase it.

### [HIGH] E-1 — `liquidate_position` binds the insurance-fund destination only *conditionally*

**Location:** `perp_engine/src/instructions/liquidate_position.rs:244-249`

```rust
if cfg.insurance_fund_balance != Pubkey::default() {
    require!(insurance_fund_balance.key() == cfg.insurance_fund_balance, ...);
}
```

The neighbouring `engine_pool` binding (`:242-243`) is unconditional — it *requires* the config
value to be set. The insurance-fund binding is not: when `cfg.insurance_fund_balance` is unset, the
caller-supplied `remaining_accounts[6]` is accepted without any check and receives `insurance_payout`.

**Why it is reachable by anyone.** `liquidate_position` is engine-operator-gated, but
`liquidator_authority` is a registered engine operator and `liquidator::liquidate` is
**permissionless** — and it forwards `ctx.remaining_accounts` through unchanged
(`liquidator/cpi_util.rs:75-82`). So an arbitrary caller controls slot 6 and can redirect the
insurance-fund share of every liquidation to an account they own.

Note this is **not** stopped by the §6 vault fix: the transfer is `engine_pool -> chosen account`
signed by `engine_authority`, which *is* a party, so the vault correctly permits it. The vault
cannot know the destination is wrong; only the engine can.

**Confirms** finding #4 of the 2026-07-24 Codex pass, which was recorded as UNVERIFIED. Verified
here at the code level, and the deployment does leave the field unset (below).

**Fix:** make the binding unconditional, matching `engine_pool` two lines above:

```rust
require!(cfg.insurance_fund_balance != Pubkey::default(), EngineError::InvalidParam);
require!(insurance_fund_balance.key() == cfg.insurance_fund_balance, EngineError::InvalidParam);
```

`set_insurance_fund_balance` (`admin.rs:95`) already exists to populate it; it simply has to become
a required part of deployment. **Not fixed** — it changes a liveness precondition on an already
mis-configured deployment (below), so it should land together with the redeploy.

### [INFO/liveness] E-2 — the deployed devnet is running stale code and cannot trade

Read directly from devnet (`engine_config` = `BwYqKbTBmLKHt46Cvdm47c8hmX2iu4H2qRnkNf81ZnqQ`):

```
perp_vault             = HDS6P815i9ZTCriGVMxvvTAY5bkToTSf8XGfPKjSpCxQ
engine_pool            = 11111111111111111111111111111111   <-- Pubkey::default()
insurance_fund_balance = 11111111111111111111111111111111   <-- Pubkey::default()
```

`bootstrap_pool.rs:138` *does* set `engine_pool`, and `scripts/devnet-state.json:49` records
`perp_engine.bootstrap_engine_pool: ok` — yet the on-chain value is still default. The deployed
binary therefore **predates the Gate 0a fix that added that write**.

Consequence: `open_position.rs:196` and `liquidate_position.rs:242` both hard-require
`cfg.engine_pool != Pubkey::default()`, so **every trade path that forwards vault accounts currently
reverts with `InvalidParam` on devnet.** The margin-lock path is dead. This fails *safe* — it is a
liveness/config defect, not a vulnerability — but it means the live devnet does not exercise the
code in this repo, and no on-chain behaviour should be inferred from it until it is redeployed.

It also means E-1 is presently masked on devnet (the `engine_pool` require fires first), and would
become live the moment `engine_pool` is set without also setting `insurance_fund_balance` — two
independent setters, so that is an easy state to land in.

---

## 4. Checked and clean (in this pass)

- `insurance_fund` — `reward.rs` binds the vault program id, applies per-call + 24h rolling caps
  before the transfer, and updates counters only after CPI success. `bootstrap_pool` is owner-only.
- `auto_deleveraging` — binds the engine program id; caps and cooldown enforced pre-CPI. Its
  operator-supplied `position_size` / `fund_balance` / `bad_debt_amount` args are a documented,
  deliberate trust assumption (`execute_adl.rs:22-34`), and fall under the §3 trust-model decision
  still open from the 2026-07-21 audit — not re-litigated here.
- `sur_timelock` — the single `invoke_signed` (`queue_exec.rs:201`) executes a queued proposal and
  is owner-gated with a guardian path; the known H-9 single-step ownership issue is unchanged.
- Ownership is two-step (`transfer_ownership` / `accept_ownership`) with a `Pubkey::default()`
  guard across all five programs.
- No `create_program_address` without canonical bump, no unchecked sysvar use, no instruction
  introspection in these five programs.

---

## 5. Status — fixes applied 2026-07-26

| Finding | Status |
|---------|--------|
| C-1 `liquidator` | ✅ **Fixed** — `constraint = perp_engine_program.key() == config.perp_engine @ LiquidatorError::InvalidProgram` (`liquidate.rs:74`). Zero state migration: `config.perp_engine` already existed and was already populated at `initialize`; it was simply never read. |
| H-1 `oracle_router` | ✅ **Fixed** — `#[account(address = perp_engine::ID @ OracleError::InvalidProgram)]` (`push_price.rs:56`). Zero state migration: `oracle_router` already depends on the `perp_engine` crate (`Cargo.toml:22`, `features = ["cpi"]`), so the id is pinned at compile time — strictly stronger than a config field, and it cannot drift. The misleading `/// CHECK: Validated by CPI runtime` comment was replaced with what actually holds. |
| A-1 `a2a_darkpool` re-rating | ⏳ **Open** — not touched in this pass. |

**Error-code hygiene:** `InvalidProgram` was **appended** to both error enums, never inserted.
Anchor derives codes from variant order (`6000 + index`), so inserting would silently renumber
already-emitted errors. Resulting codes: `LiquidatorError::InvalidProgram = 6005`,
`OracleError::InvalidProgram = 6014`.

**Regression test:** `tests/13_arbitrary_cpi_regression.ts`. Each finding is asserted twice —
a foreign program id (the System Program: real and executable, so the guard is proven to reject on
*identity*, not on "not executable") must revert with `InvalidProgram`, **and** the canonical
`perp_engine` must get past the guard. The second half is what stops the test from passing
vacuously if the constraint were ever deleted.

### Verification performed

| Check | Result |
|-------|--------|
| `cargo check -p liquidator -p oracle_router` (forced rebuild) | ✅ clean — no errors; only pre-existing `cfg`/`realloc` warnings |
| `cargo check --workspace` | ✅ clean |
| Patched `idl/*.json` + `clients/web/idls/*.json` parse as JSON | ✅ all 4 valid |
| Account names in the new test vs. committed IDL | ✅ exact match for `liquidate` and `push_price` |
| `tsc --noEmit` on `tests/13_arbitrary_cpi_regression.ts` | ✅ clean (uses `.accountsPartial()`; note the pre-existing `tests/06_liquidator.ts` emits 8 errors of this class under the same flags) |

### NOT verified — and why

**The regression test has never been executed.** Per `TEST-STATUS.md`, `anchor test` has never run
green in this repo at all: `solana-test-validator` wedges on Windows, and CI is a build-only gate
because pinning program IDs would require committing program keypairs (declined by project rule).
The fixes are verified by compilation and by code review; the test is verified by typecheck only.

**To actually run it** (Linux/macOS, or CI with committed program keypairs):
```bash
anchor build --no-idl -- --tools-version v1.52
cp types/*.ts target/types/          # stage committed types
anchor test --skip-build
```
Expected: the two "rejects a foreign CPI target program" cases pass **only** with these fixes in
place; reverting either constraint must turn the corresponding case red.

Regenerating the IDL was not possible (Anchor 0.31.1's IDL build is broken against this dependency
tree — `TEST-STATUS.md` §CI). The committed `idl/`, `types/`, and `clients/web/idls/` artifacts were
therefore hand-patched with the two new error entries and verified to parse; no account or
instruction shape changed, so nothing else in those files went stale.
