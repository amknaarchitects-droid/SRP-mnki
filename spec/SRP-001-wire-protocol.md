# SRP-001: Wire Protocol Specification

**Status:** Draft Standard (v0.1.0)  
**Category:** Core Protocol  
**License:** MIT / Public Domain (CC0)

---

## 1. Abstract

SRP-001 defines the transport-agnostic message format and state machine between **AI Lab Trainers / Rollout Collectors**, **SRP Coordinators**, and **SRP Provider Nodes**. The protocol enables low-overhead remote management of in-memory Copy-on-Write (CoW) reinforcement learning (RL) snapshots, deterministic step execution, and cryptographic verification receipts.

---

## 2. Design Principles

1. **Send Actions, Not States:** Base environment snapshots (`SnapshotManifest`) are loaded into node RAM once. Subsequent multi-turn RL rollouts exchange only compact action payloads (~1–4 KB) and delta observations.
2. **First-Class Tree Branching (`SRP_FORK`):** Unlike standard container orchestrators that treat every rollout as an isolated boot sequence, SRP makes `SRP_FORK` a primitive wire operation, allowing $G$-way branching (e.g., for GRPO or MCTS) in $<2\text{ ms}$.
3. **Cryptographic Traceability:** Every state transition produces a deterministic hash chain (`parent_state_hash -> action_hash -> next_state_hash`).

---

## 3. Core Message Types

All messages are serialized as UTF-8 JSON-RPC 2.0 frames (or binary MessagePack/Protobuf equivalents) with optional `zstd` compression on memory delta blobs.

### 3.1. `NODE_REGISTER` (Provider $\rightarrow$ Coordinator)
Registers a contributor node's bounded RAM Arena capacity and supported sandbox runtimes.

```json
{
  "type": "NODE_REGISTER",
  "node_id": "srp_node_9f8a7b6c",
  "public_key_hex": "d4e5f6...",
  "ram_arena_capacity_mb": 16384,
  "supported_runtimes": ["wasm_cow", "container_tmpfs"],
  "supported_suites": ["srp-env-code", "srp-env-math", "srp-env-web", "srp-env-spatial"],
  "protocol_version": "0.1.0"
}
```

### 3.2. `SNAPSHOT_PIN` (Coordinator $\rightarrow$ Provider)
Instructs the provider node to pin a read-only base environment image ($S_0$) inside its volatile RAM Arena.

```json
{
  "type": "SNAPSHOT_PIN",
  "snapshot_id": "snap_lean4_mathlib_v4.12",
  "suite": "srp-env-math",
  "runtime": "wasm_cow",
  "memory_footprint_mb": 512,
  "content_merkle_root": "sha256:8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
  "initial_files": {
    "Main.lean": "import Mathlib\n..."
  }
}
```

### 3.3. `SRP_FORK` (Coordinator $\rightarrow$ Provider)
Creates $N$ Copy-on-Write branches from either a pinned base snapshot ($S_0$) or an existing mid-rollout branch ($B_k$).

```json
{
  "type": "SRP_FORK",
  "source_id": "snap_lean4_mathlib_v4.12",
  "branch_count": 16,
  "ttl_seconds": 300
}
```

**Response (`SRP_FORK_ACK`):**
```json
{
  "type": "SRP_FORK_ACK",
  "source_id": "snap_lean4_mathlib_v4.12",
  "branch_ids": ["br_001", "br_002", "..."],
  "fork_latency_ms": 0.42,
  "dirty_ram_bytes": 0,
  "state_hash": "sha256:8f4343..."
}
```

### 3.4. `SRP_STEP` (Coordinator $\rightarrow$ Provider)
Executes a single agent action (e.g., code patch, proof tactic, DOM click, or CAD script) inside a specific CoW branch and computes the verifiable reward.

```json
{
  "type": "SRP_STEP",
  "request_id": "req_7712",
  "branch_id": "br_001",
  "action": {
    "command": "verify_tactic",
    "payload": "simp [Nat.add_comm]"
  },
  "timeout_ms": 5000
}
```

**Response (`SRP_STEP_RESULT`):**
```json
{
  "type": "SRP_STEP_RESULT",
  "request_id": "req_7712",
  "branch_id": "br_001",
  "observation": {
    "stdout": "Goals accomplished!",
    "stderr": "",
    "exit_code": 0
  },
  "reward": 1.0,
  "terminated": true,
  "truncated": false,
  "metrics": {
    "exec_time_ms": 12.4,
    "dirty_pages": 14,
    "dirty_bytes": 57344
  },
  "receipt": {
    "node_id": "srp_node_9f8a7b6c",
    "parent_state_hash": "sha256:8f4343...",
    "action_hash": "sha256:3a1f9c...",
    "next_state_hash": "sha256:e9b211...",
    "dirty_page_merkle_root": "sha256:c0ffee...",
    "signature": "hmac_sha256:9981ab..."
  }
}
```

### 3.5. `SRP_EVICT` (Coordinator $\rightarrow$ Provider)
Immediately drops one or more branches or base snapshots from the volatile RAM Arena, zeroing the underlying memory pages.
