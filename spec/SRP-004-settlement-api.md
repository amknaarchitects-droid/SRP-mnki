# SRP-004: General Economic & Settlement Interface Specification

**Status:** Draft Standard (v0.5.0)  
**Category:** Economics & Incentives  
**License:** MIT / Public Domain (CC0)

---

## 1. Philosophy: Public Good, Agnostic Economics

SRP charges **0% protocol fees** and does not mandate a proprietary token or payment processor. It defines an auditable **metering & settlement interface (`SettlementProvider`)** that any AI company, research consortium, or decentralized network can implement.

---

## 2. Dual-Component Metering

For billing epoch $e$, node $i$'s metered value is

$$V_{i,e} = \alpha \cdot \sum_{c \in \text{PassedChallenges}_{i,e}} \text{PinnedGB}_c \cdot \Delta t_c \;+\; \beta \cdot \sum_{s \in \text{VerifiedSteps}_{i,e}} w(s)$$

* **RAM leases** accrue only across intervals that end in a **passed** chained residency challenge (SRP-003 §2.3), and only for the node's **ballast bytes**: snapshot pages are public and cannot prove residency. Deployments price the ballast size (`ballast_ratio` × distinct snapshot pages) and $\alpha$ together. $\Delta t_c$ is the time since the previous challenge, capped at `max_lease_interval_s`. Pinning alone earns nothing; a failed challenge forfeits the interval; quarantined nodes earn nothing.
* **Steps** are credited after Layer-1 verification and any Layer-2 audit pass. $w(s) = 1 + \gamma \cdot \text{NewDirtyMB}(s)$, which bills only the *signed* `step_dirty_pages`, capped per step (`max_billable_dirty_pages`). Steps that hit the wall-clock backstop earn nothing.

## 3. Interface

```python
class SettlementProvider(Protocol):
    unit_symbol: str
    def record_ram_lease(self, node_id, pinned_bytes, duration_seconds) -> SettlementReceipt: ...
    def record_verified_step(self, node_id, compute_ms, dirty_pages) -> SettlementReceipt: ...
    def record_canary_failure(self, node_id, fraud_proof) -> SettlementReceipt: ...
    def get_account(self, node_id) -> SettlementAccount: ...
    def summary(self) -> dict: ...
```

`record_canary_failure` MUST refuse proofs that are not self-contained and third-party verifiable (`FraudProof.slashable`). The reference `BaseConfigurableLedger` additionally provides `deposit_stake`, `stake_of`, `request_unbond`, `withdraw_unbonded`, `reverse_slash`, `close_epoch` and `compute_payout_merkle_root`.

## 4. Stake, Slashing and Sybil Resistance

* Nodes may deposit **stake**. A coordinator can require `min_stake_units` before accepting `NODE_REGISTER`.
* A slash removes `slash_penalty_units`, taken from the **unsettled** balance first, then from active stake, then from unbonding stake. Earnings that were already paid out are never treated as a substitute for stake.
* **Unbonding:** `request_unbond` moves stake into an unbonding queue that stays slashable for `unbonding_period_s` before `withdraw_unbonded` releases it.
* **Quarantine:** a slashed node gets no new work, and neither its `node_id` nor its key can re-register. `min_stake_units` is re-checked before routing, not only at registration.
* **Appeals:** a slash overturned on appeal (SRP-003 §2.4) is refunded via `reverse_slash`. Given the slash's receipt id, each part goes back where it came from (the unsettled balance or stake); without it the whole amount is credited to stake.
* **Amounts:** stake deposits, unbonds and refunds MUST be finite; deposits and unbonds MUST be positive.
* **Choosing parameters.** Faking steps is unprofitable in expectation when $\text{stake} \cdot \text{audit\_rate} \gtrsim \beta$ per step. Faking a reward is unprofitable when $\text{slash\_penalty} \cdot \text{rewarded\_audit\_rate} \gtrsim$ the value of one fabricated reward (SRP-003 §2.2). With no stake requirement, the only cost of a new identity is the work needed to build a balance, so permissionless networks SHOULD require stake.
* **Pricing.** For paid capacity to make sense, the contributor rate must undercut the datacenter price once auditor overhead is included: $\alpha < (1 - a) \cdot c_{dc}$, where $a$ is the share of work duplicated by audits and $c_{dc}$ the datacenter price per GiB-hour (about \$0.0036–0.0083 in November 2026; see `docs/ECONOMICS.md` §4.2). The USD and stablecoin reference ledgers default to example rates derived this way: $\alpha = 0.002$ per GB-hour, $\beta = 0.000001$ per step (about 50 ms of datacenter vCPU), and $\gamma = 0$ (one dirty MB held for an hour is worth less than the ledger's micro-unit resolution). These are examples, not recommendations; the karma ledger is unpriced points.

## 5. Epoch Payouts

`close_epoch()` snapshots every account's unsettled amount (balance minus already-settled) in integer micro-units, marks those amounts settled, and commits to them with a Merkle root over the leaves

```
leaf = SHA256(JSON["SRP_PAYOUT_V1", epoch, node_id, amount_micro, unit_symbol])
```

using the domain-separated Merkle tree of SRP-002 §2.4. Leaves are unambiguous (JSON-encoded, so delimiters inside a `node_id` cannot collide) and bound to one epoch, so a claim proof cannot be replayed in a later epoch. A claim contract only needs to track which epochs each node has claimed.

## 6. Reference Adapters (`srp/settlement/`)

1. **`FiatAndApiCreditLedger`:** USD payouts or API/subscription credits.
2. **`TokenEscrowLedger`:** USDC/ERC-20/SPL settlement via epoch Merkle roots.
3. **`OpenScienceKarmaLedger`:** volunteer-compute karma for open-science campaigns.
