# SRP-004: General Economic & Settlement Interface Specification

**Status:** Draft Standard (v0.1.0)  
**Category:** Economics & Incentives  
**License:** MIT / Public Domain (CC0)

---

## 1. Philosophy: Public Good, Agnostic Economics

SRP charges **0% protocol fees** and does not mandate a proprietary token or centralized payment processor. Instead, SRP defines a clean, auditable **Metering & Settlement Interface (`SettlementProvider`)** that any AI company, research consortium, or decentralized network can implement to compensate RAM contributors according to their own economic model.

---

## 2. Dual-Component Metering Formula

Contributors provide two distinct resources to AI model trainers:
1. **Pinned RAM Capacity ($\text{GB}\cdot\text{Hours}$):** Keeping environment base snapshots and paused rollout branches hot in volatile RAM so the trainer can fork/step with zero cold-start latency.
2. **Verified Verifier Execution ($\text{Step}\cdot\text{Units}$):** Actively executing environment transitions and computing verifiable rewards.

For a billing epoch $e$, a contributor node $i$'s metered value $V_{i,e}$ is computed by the Coordinator's settlement adapter as:

$$V_{i,e} = \Big(\alpha \cdot \int_{t \in e} \text{PinnedRAM}_i(t)\,dt\Big) + \Big(\beta \cdot \sum_{s \in \text{VerifiedSteps}_{i,e}} w(s)\Big)$$

where:
* $\alpha$ is the company-defined rate per $\text{GB}\cdot\text{Hour}$ of verified hot RAM.
* $\beta$ is the company-defined rate per verified RL environment step.
* $w(s)$ is an optional step complexity weight (based on dirty memory pages + execution milliseconds).

---

## 3. Standard Settlement Adapters

SRP ships with three reference implementations in `srp/settlement/`:

1. **`FiatAndApiCreditLedger`:** For AI model companies (e.g., Anthropic, OpenAI, Together, Fireworks) to reward users directly with **USD payouts (Stripe Connect)** or **API / Subscription Credits**.
2. **`TokenEscrowLedger`:** For Web3 / DePIN networks or DAOs to settle rewards in **USDC, USDT, or custom ERC-20 / SPL tokens** via cryptographic Merkle roots.
3. **`OpenScienceKarmaLedger`:** For universities, non-profits, and open-source AI collectives running volunteer compute campaigns (BOINC / Folding@Home style) with verifiable contributor certificates.
