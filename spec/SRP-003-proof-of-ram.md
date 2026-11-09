# SRP-003: Proof-of-Honest-RAM (PoHR) & Verification Specification

**Status:** Draft Standard (v0.1.0)  
**Category:** Security & Cryptographic Verification  
**License:** MIT / Public Domain (CC0)

---

## 1. Threat Model

In an open, permissionless network where contributors earn compensation (fiat, API credits, or tokens) from AI companies, adversarial nodes may attempt three classes of attacks:

1. **Lazy Spoofing Attack:** Returning fake rewards (e.g., always returning `reward: 1.0` or random rewards) without executing the sandbox.
2. **SSD-Swap Masquerade Attack:** Advertising 128 GB of "RAM" that is actually backed by a slow NVMe/HDD swap file, degrading rollout throughput.
3. **Reward Poisoning Attack:** Intentionally flipping rewards on specific trajectories to corrupt an AI model's RL training gradient.

---

## 2. Three-Layer Defense Mechanism

### Layer 1: Deterministic Merkle Execution Receipts
Every `SRP_STEP` must return a cryptographic `ExecutionReceipt`:

$$\text{StateHash}_{t} = \text{SHA256}\Big(\text{StateHash}_{t-1} \parallel \text{MerkleRoot}(\text{DirtyPages}_{t})\Big)$$

$$\text{ReceiptHash} = \text{SHA256}\Big(\text{StateHash}_{t-1} \parallel \text{SHA256}(\text{Action}) \parallel \text{StateHash}_{t} \parallel \text{SHA256}(\text{Stdout}) \parallel \text{Reward}\Big)$$

A lazy node cannot guess $\text{StateHash}_{t}$ or the exact `DirtyPages` Merkle root without actually executing the step inside the CoW memory arena.

### Layer 2: Blind Canary Injection (`CanaryVerifier`)
The Coordinator maintains a dynamic pool of **Canary Tasks**—synthetic or previously verified rollout steps with known deterministic outputs, state hashes, and rewards.
* Canary steps are indistinguishable on the wire from live RL steps.
* By default, $3\% - 5\%$ of dispatched steps to any node are canaries.
* **Zero-Tolerance Fraud Proof:** If a node's returned `ReceiptHash` or `Reward` mismatches the canary's expected ground truth, the Coordinator generates a signed `FraudProof`, invalidates the node's unverified batch, and triggers `SettlementProvider.on_canary_failure()`.

### Layer 3: Memory-Speed Challenge (Anti-Swap SLA)
To verify that pinned snapshots truly reside in physical DRAM rather than disk swap:
* During `SRP_FORK` and random page reads (`SRP_MEMORY_PING`), the Coordinator challenges the node to compute an XOR-fold or SHA-256 digest over $K$ pseudo-randomly selected 4 KB pages from a pinned snapshot using a seed derived from the challenge nonce.
* Physical DRAM completes a 64-page random read challenge in $<1\text{ ms}$, whereas disk-backed swap experiences page-fault latencies orders of magnitude higher.
