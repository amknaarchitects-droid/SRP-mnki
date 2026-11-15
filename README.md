# Share RAM Protocol (SRP)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Protocol Version](https://img.shields.io/badge/SRP-v0.7.0-brightgreen.svg)](spec/SRP-001-wire-protocol.md)
[![Protocol Fee](https://img.shields.io/badge/Protocol_Fee-0%25-orange.svg)](spec/SRP-004-settlement-api.md)
[![Status](https://img.shields.io/badge/Status-Alpha-red.svg)](ROADMAP.md)

> **An Open-Source Public Good for Humanity:** Turn the world's spare consumer and workstation RAM into a zero-disk-wear, Copy-on-Write (CoW) in-memory execution and verification fabric for AI Reinforcement Learning (RL) post-training.

**Status: alpha.** This is a specification and a reference implementation with simulated environments. See the [roadmap](ROADMAP.md) for what comes next.

**Where SRP fits, honestly.** Our [economics and latency analysis](docs/ECONOMICS.md) finds that SRP does **not** beat renting datacenter RAM for paid capacity, and that it is a poor fit for tight environment loops over the internet: every call costs a network round trip, which dwarfs a sub-millisecond environment step. Its credible use is **donated capacity** (for example open-science runs) for **latency-tolerant, multi-turn workloads**, where each turn involves seconds of model generation. The Copy-on-Write arena is useful on its own, inside or outside a datacenter.

Created and maintained by **Shady Sharaf (mnki)**.

---

## Why SRP Exists

As frontier AI shifts toward **Reinforcement Learning with Verifiable Rewards (RLVR)**, **Group Relative Policy Optimization (GRPO)**, and **Monte Carlo Tree Search (MCTS)**, the primary infrastructure bottleneck is no longer just GPU FLOPs—it is **System RAM for parallel environment sandboxes**:

* **Mostly Idle Memory (estimate):** During multi-turn RL rollouts (coding, formal math, web navigation, 3D CAD), each sandbox executes an action for a short time and then sits frozen in RAM waiting for the GPU cluster to generate the next reasoning token. We expect sandboxes to be idle for the large majority of a rollout; this has not been measured yet.
* **The Container RAM Wall (worked example):** 100,000 isolated containers at 500 MB–2 GB each would need 50 TB to 200 TB of system RAM. The container count and sizes are illustrative assumptions, not figures from a specific training run. Copy-on-Write sharing shrinks this figure in a datacenter just as much as on contributor machines.
* **Zero Disk Wear by Design:** Unlike traditional distributed compute networks that thrash contributor SSDs, SRP keeps all environment state **in volatile RAM (`VolatileRAMArena`)** using **4 KB page-granular Copy-on-Write (CoW)** snapshots. Forked branches share the immutable base pages and allocate only the pages they change, with **zero bytes written to disk**. Measured at the OS level, 64 branches forked from a 64 MB snapshot, each writing 16 KB, used **98% less memory** than 64 full copies ([benchmark](benchmarks/results/RESULTS.md)). A pinned snapshot itself costs about 1.15× its size in process memory ([analysis](docs/ECONOMICS.md#23-memory-saved-by-copy-on-write)).

---

## Core Architecture

```
┌─────────────────────────────────────────────────────────────┐
│      AI LAB / TRAINER (any RLVR / GRPO training stack)      │
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
│  │  ├── srp-env-math    (Lean-style toy proof states)    │  │
│  │  ├── srp-env-web     (Simulated In-Memory DOM)        │  │
│  │  └── srp-env-spatial (3D CAD Geometry & CoM Physics)  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

The four bundled environment suites are small simulations written in Python (a Lean-style tactic checker, a DOM state machine, a CAD geometry verifier and a sandboxed code grader). They exercise the protocol end to end; they are not Lean 4, a real browser or production containers.

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

# 2. Fork 16 parallel Copy-on-Write branches (sub-millisecond in the demo)
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

## Security Model (v0.7.0)

| Layer | What it guarantees |
|---|---|
| **Node identity** | Ed25519 key per node, with proof-of-possession at `NODE_REGISTER`. Quarantine binds both the id and the key, and survives restarts (`state_path`). |
| **Receipts (V3)** | Sign the whole observation, billed metrics and timeout. They are bound to the coordinator's request id, coordinator-minted branch ids, the step index and the coordinator's own copy of the hash chain. Rewards must be finite. |
| **Correctness** | Blind, incremental replay audits on an auditor with the same runtime profile (Python version, hash algorithm, OS and CPU architecture). Every committed step since the last checkpoint is re-checked. Timed-out steps are always audited, and rewarded or terminal steps are audited with probability `rewarded_audit_rate` (default 1.0: always). A mismatch must be confirmed by repeated runs. Canaries run at random depths; a canary that hits the wall-clock backstop is inconclusive, never fraud. |
| **Evidence** | Slashable fraud proofs are self-contained (signed receipt + lineage + manifest identity), and the receipt must be for the lineage's last step. Anyone can re-check them with `verify_fraud_proof_by_replay`. Appeals refund the slash to where it came from, and reinstate the node only if nothing else stands against it. |
| **RAM residency** | Chained (pointer-chasing) challenges over time-memory-hard, node-unique ballast, with the RTT baseline subtracted. Only proven ballast bytes earn lease. |
| **Agent code** | Static policy, deterministic fuel, process isolation, an audit hook blocking every CPython audit event, address scrubbing, and hash-order-deterministic sets. The tests run in a separate namespace and the test file is hidden. On Linux, the sandbox also adds a network namespace, seccomp-BPF (x86_64 and aarch64), no-ASLR and rlimits. |
| **Grading** | Pinned tests can use seeded property helpers (`srp_randint`, `srp_choice`, `srp_random`). The seed depends on a hidden salt and the submitted code, so visible examples cannot simply be hard-coded. |
| **Transport** | `srp/transport`: Ed25519-signed commands (with timestamp and single-use nonce), signed responses, strict schema validation, deadlines, and optional TLS/mTLS (tested), with handshakes off the accept thread. Persistent connections; a retry re-sends the identical signed frame, so a command never runs twice. |
| **Economics** | Stake with unbonding, slashing from unsettled balance and then stake, quarantine, and epoch-bound payout Merkle roots. |

**Known limits:**
- Windows nodes have no kernel-level network filter. Set `require_kernel_isolation=True` to admit only Linux nodes.
- Determinism is guaranteed only within a runtime profile.
- Property tests only help if snapshot authors write them.

The protocol is **alpha**: get an external security review before running it permissionlessly; [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md) is the starting point. [SRP-003 §5](spec/SRP-003-proof-of-ram.md) lists these residual risks.

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

Some sandbox tests need Linux kernel features and are skipped on other systems. CI runs the suite, the demo and a benchmark smoke run on Linux and Windows, plus `bandit` and `pip-audit`.

## Benchmarks

```bash
pip install -e ".[crypto,dev,bench]"
python -m benchmarks
```

Measures step latency, throughput under simulated network round-trip times, OS-level memory saved by Copy-on-Write, and replay-audit overhead. Results are written to [`benchmarks/results/`](benchmarks/results/RESULTS.md) and analysed in [docs/ECONOMICS.md](docs/ECONOMICS.md).

---

## Development Process

SRP was developed with AI coding assistance (Anthropic's Claude and Google's Gemini), directed and reviewed by the maintainer. Treat it accordingly: the behavior it claims is pinned by the test suite and the specs in `spec/`, and it has not yet had an independent security review.

## Roadmap and Contributing

* [ROADMAP.md](ROADMAP.md): what is planned, and what SRP is not (yet).
* [CHANGELOG.md](CHANGELOG.md): what changed in each release.
* [CONTRIBUTING.md](CONTRIBUTING.md): setup, rules and how to report security issues.
* [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md): scope, threat model, where each security claim lives in the code, and known limits.

---

## License

Released under the **MIT License** for the benefit of humanity.
