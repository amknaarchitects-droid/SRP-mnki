# Share RAM Protocol (SRP)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Protocol Version](https://img.shields.io/badge/SRP-v0.3.0-brightgreen.svg)](spec/SRP-001-wire-protocol.md)
[![Protocol Tax](https://img.shields.io/badge/Protocol_Fee-0%25_Forever-orange.svg)](spec/SRP-004-settlement-api.md)

> **An Open-Source Public Good for Humanity:** Turn the world's spare consumer and workstation RAM into a zero-disk-wear, Copy-on-Write (CoW) in-memory execution and verification fabric for AI Reinforcement Learning (RL) post-training.

---

## Why SRP Exists

As frontier AI shifts toward **Reinforcement Learning with Verifiable Rewards (RLVR)**, **Group Relative Policy Optimization (GRPO)**, and **Monte Carlo Tree Search (MCTS)**, the primary infrastructure bottleneck is no longer just GPU FLOPs—it is **System RAM for parallel environment sandboxes**:

* **95%+ Idle Memory Wait:** During multi-turn RL rollouts (coding, formal math, web navigation, 3D CAD), each sandbox executes an action for a few milliseconds and then sits frozen in RAM waiting for the GPU cluster to generate the next reasoning token.
* **The Container RAM Wall:** Running 100,000 isolated containers at 500 MB–2 GB each requires **50 TB to 200 TB of system RAM**.
* **Zero Disk Wear by Design:** Unlike traditional distributed compute networks that thrash contributor SSDs, SRP keeps all environment state **in volatile RAM (`VolatileRAMArena`)** using **4 KB page-granular Copy-on-Write (CoW)** snapshots. When an AI model forks 32 parallel GRPO branches from a 500 MB environment snapshot, SRP shares the immutable base pages in RAM and allocates only the ~16 KB of mutated delta pages per branch—saving **95%+ of physical RAM** with **zero bytes written to disk**.

---

## Core Architecture

```
┌─────────────────────────────────────────────────────────────┐
│        AI LAB / TRAINER (Anthropic, OpenAI, Prime-RL)       │
│   [GPU Cluster: Secret Model Weights Stay 100% In-House]    │
└──────────────┬────────────────────────────────▲─────────────┘
               │ 1. SRP_FORK / SRP_STEP         │ 4. Ed25519-Signed Receipt
               │    (Compact Action Payload)    │    + Verifiable Reward
               ▼                                │
┌───────────────────────────────────────────────┴─────────────┐
│             SRP COORDINATOR & VERIFICATION MESH             │
│   • Snapshot-Aware Consistent Routing                       │
│   • Blind Replay Audits, Canaries & Ballast RAM Challenges  │
│   • Agnostic Settlement API (USD/Credits, Tokens, or Karma) │
└──────────────┬────────────────────────────────▲─────────────┘
               │                                │
               ▼                                │
┌───────────────────────────────────────────────┴─────────────┐
│            SRP PROVIDER NODE (Contributor's Spare RAM)      │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  VolatileRAMArena (4 KB Content-Addressed CoW Pages)  │  │
│  │  ├── srp-env-code    (SWE Unit-Test & AST Sandbox)    │  │
│  │  ├── srp-env-math    (Lean 4 / Formal Proof State)    │  │
│  │  ├── srp-env-web     (Headless In-Memory DOM Tree)    │  │
│  │  └── srp-env-spatial (3D CAD Geometry & CoM Physics)  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Quickstart

### 1. Run the End-to-End 4-Suite Benchmark & Demo
```bash
python -m srp.cli demo
```

### 2. Use SRP in 5 Lines of Python (Gymnasium / GRPO Bridge)
```python
import srp
from srp.cli import build_default_manifests

# 1. Spin up an in-memory CoW environment from any SnapshotManifest
manifests = build_default_manifests()
env = srp.make(manifests["math"])

# 2. Fork 16 parallel Copy-on-Write branches in < 0.5 ms!
branches = env.fork(count=16)

# 3. Step any branch independently in volatile RAM
obs, reward, terminated, truncated, info = branches[0].step({
    "command": "apply_tactic",
    "payload": {"tactic": "rw [Nat.add_assoc]"}
})
print(f"Reward: {reward}, Dirty 4KB Pages: {info['dirty_pages']}, Receipt: {info['receipt'].signature[:16]}...")
```

### Install
```bash
pip install -e ".[crypto,dev]"
```
The `crypto` extra installs `cryptography` for fast, constant-time Ed25519; without it SRP falls back to a pure-Python RFC 8032 implementation (correct, but slower and not side-channel resistant).

### 3. Plug in Any Economic Model (`SettlementProvider`)
SRP is a public good with **0% protocol fees** and is completely agnostic to how AI companies compensate contributors:
* **`FiatAndApiCreditLedger`**: Reward contributors in USD (Stripe Connect) or AI API / subscription credits.
* **`TokenEscrowLedger`**: Settle rewards in USDC or custom ERC-20 / SPL tokens with cryptographic Merkle claim roots.
* **`OpenScienceKarmaLedger`**: BOINC / Folding@Home style public-good karma for open-science post-training runs.

---

## Security Model (v0.3.0)

| Layer | What it guarantees |
|---|---|
| **Node identity** | Ed25519 key per node, with proof-of-possession at `NODE_REGISTER`. Quarantine binds both the id and the key, and survives restarts (`state_path`). |
| **Receipts (V3)** | Sign the whole observation, billed metrics and timeout. They are bound to the coordinator's request id, coordinator-minted branch ids, the step index and the coordinator's own copy of the hash chain. Rewards must be finite. |
| **Correctness** | Blind, incremental replay audits on an auditor with the same runtime profile. Every committed step since the last checkpoint is re-checked, and rewarded, terminal and timed-out steps are always audited. A mismatch must be confirmed by repeated runs. Canaries run at random depths. |
| **Evidence** | Slashable fraud proofs are self-contained (signed receipt + lineage), and anyone can re-check them with `verify_fraud_proof_by_replay`. Appeals can reinstate a node and refund its slash. |
| **RAM residency** | Chained (pointer-chasing) challenges over time-memory-hard, node-unique ballast, with the RTT baseline subtracted. Only proven ballast bytes earn lease. |
| **Agent code** | Static policy, deterministic fuel, process isolation, an audit hook blocking every CPython audit event, and address scrubbing. The tests run in a separate namespace and the test file is hidden. On Linux, the sandbox also adds a network namespace, seccomp-BPF, no-ASLR and rlimits. |
| **Transport** | `srp/transport`: Ed25519-signed commands (with timestamp and single-use nonce), signed responses, strict schema validation, deadlines, optional TLS. |
| **Economics** | Stake with unbonding, slashing from unsettled balance and then stake, quarantine, and epoch-bound payout Merkle roots. |

**Known limits:**
- Windows nodes have no kernel-level network filter. Set `require_kernel_isolation=True` to admit only Linux nodes.
- Determinism is guaranteed only within a runtime profile.
- Fixed unit tests can still be over-fitted.

The protocol is **alpha**: get an external security review before running it permissionlessly. [SRP-003 §5](spec/SRP-003-proof-of-ram.md) lists these residual risks.

### Multi-host deployment
```python
from srp.transport import NodeServer, RemoteNode
server = NodeServer(node, coordinator_public_key_hex=coord.keypair.public_key_hex, host="0.0.0.0", port=8443,
                    ssl_context=tls_ctx).start()                                  # on the contributor host
coord.register_node(RemoteNode("https://host:8443/srp/v1", coord.keypair, node_id=node.node_id,
                               ssl_context=client_tls_ctx))                       # on the coordinator
```

---

## Formal Specifications (`spec/`)

* **[SRP-001: Wire Protocol Specification](spec/SRP-001-wire-protocol.md)** — JSON-RPC framing (`srp/protocol/wire.py`), `NODE_REGISTER`, `SNAPSHOT_PIN`, `SRP_BALLAST_PIN`, `SRP_FORK`, `SRP_STEP`, `SRP_EVICT`.
* **[SRP-002: Copy-on-Write Volatile RAM Arena](spec/SRP-002-cow-ram-arena.md)** — 4 KB page tables, multi-turn tree branching, and zero-disk-wear guarantees.
* **[SRP-003: Proof-of-Honest-RAM (PoHR)](spec/SRP-003-proof-of-ram.md)** — Signed receipts, blind replay audits, canaries, ballast residency challenges, and the code sandbox.
* **[SRP-004: General Economic & Settlement API](spec/SRP-004-settlement-api.md)** — Verified GB·hours + verified steps, stake & slashing, and epoch payout roots.

---

## Running Tests

```bash
pytest -v
```

---

## License

Released under the **MIT License** for the benefit of humanity.
