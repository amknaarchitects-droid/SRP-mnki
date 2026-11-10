# SRP-001: Wire Protocol Specification

**Status:** Draft Standard (v0.4.0)  
**Category:** Core Protocol  
**License:** MIT / Public Domain (CC0)

---

## 1. Abstract

SRP-001 defines the transport-agnostic message format and state machine between **AI Lab Trainers / Rollout Collectors**, **SRP Coordinators**, and **SRP Provider Nodes**. The protocol enables low-overhead remote management of in-memory Copy-on-Write (CoW) reinforcement learning (RL) snapshots, deterministic step execution, and signed verification receipts.

---

## 2. Design Principles

1. **Send Actions, Not States:** Base environment snapshots (`SnapshotManifest`) are loaded into node RAM once. Subsequent multi-turn RL rollouts exchange only compact action payloads (~1–4 KB) and delta observations.
2. **First-Class Tree Branching (`SRP_FORK`):** `SRP_FORK` is a primitive wire operation, allowing $G$-way branching (e.g., for GRPO or MCTS) from a snapshot or from any live branch.
3. **Verifiable Traceability:** Every state transition is reported in an Ed25519-signed receipt binding `parent_state_hash -> action_hash -> next_state_hash` to the coordinator's request, the root snapshot, and the branch's step index.
4. **Determinism:** Verifier suites must be deterministic functions of (state, action) so that any party can replay a branch lineage and reproduce every receipt (see SRP-003 §2.2).

---

## 3. Framing

Every message is a UTF-8 JSON-RPC 2.0 frame (reference codec: `srp/protocol/wire.py`):

```json
{"jsonrpc": "2.0", "id": "7f3c…", "method": "SRP_STEP",
 "params": {"srp_version": "0.4.0", "body": { … message fields … }}}
```

Receivers MUST reject frames with an unknown `method`, a different `srp_version`, unknown body fields, non-finite numbers (`NaN`, `Infinity`), or a size above 16 MiB. Binary MessagePack/Protobuf encodings with identical field names are permitted; optional `zstd` compression applies to page blobs only.

---

## 4. Core Message Types

### 4.1. `NODE_REGISTER` (Provider → Coordinator)

```json
{
  "node_id": "srp_node_9f8a7b6c",
  "public_key_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  "ram_arena_capacity_mb": 16384,
  "supported_runtimes": ["wasm_cow", "container_tmpfs"],
  "supported_suites": ["srp-env-code", "srp-env-math", "srp-env-web", "srp-env-spatial"],
  "protocol_version": "0.4.0",
  "runtime_profile": "cpython-3.12-siphash13-linux",
  "sandbox_isolation": {"kernel_network_isolation": true, "seccomp": true, "network_namespace": true}
}
```

`public_key_hex` is a raw 32-byte Ed25519 public key. Registration is a challenge–response: the coordinator sends a random nonce and the node returns an Ed25519 signature over

```
SRP_NODE_REGISTER_V1|<node_id>|<public_key_hex>|<nonce>
```

A coordinator MUST reject:
* a failed proof;
* a `node_id` already bound to a different key;
* a quarantined `node_id` *or public key*;
* a different `protocol_version`;
* a `runtime_profile` for which it has no auditor (SRP-003 §2.2);
* if it enforces one, a stake below the minimum (SRP-004 §4);
* if required, a node without kernel-level sandbox isolation.

### 4.2. `SNAPSHOT_PIN` (Coordinator → Provider)

```json
{
  "snapshot_id": "snap_lean4_mathlib_v4.12",
  "suite": "srp-env-math",
  "runtime": "wasm_cow",
  "initial_files": {"Main.lean": "import Mathlib\n..."},
  "metadata": {}
}
```

The snapshot's `content_merkle_root` is derived from `initial_files` (SRP-002 §2.4) and is not transmitted; the node MUST compute it and report the same value. A node that already holds `snapshot_id` with different content MUST refuse the pin (`snapshot_id`s are content-unique).

### 4.3. `SRP_BALLAST_PIN` (Coordinator → Provider)

```json
{"snapshot_id": "snap_lean4_mathlib_v4.12", "seed_hex": "5be1…", "page_count": 4096}
```

A node-unique seed, derived from a coordinator-only master secret. The node expands it locally into `page_count` sequentially dependent 4 KB pages (SRP-003 §2.3), so no bulk transfer is needed. Ballast counts against the node's RAM ceiling and is released with the snapshot.

### 4.4. `SRP_FORK` (Coordinator → Provider)

```json
{"source_id": "snap_lean4_mathlib_v4.12", "branch_count": 2, "ttl_seconds": 300,
 "branch_ids": ["br_7c0e…", "br_91aa…"]}
```

Branch ids are **minted by the coordinator**. The node MUST create exactly those ids, and refuse any id that is already in use.

`source_id` is a pinned snapshot or an existing branch. Forking a branch is atomic with respect to steps on that branch. When `ttl_seconds` is set, the node evicts each branch once the TTL elapses (also enforced lazily on access).

**Response (`SRP_FORK_ACK`):**
```json
{"source_id": "snap_lean4_mathlib_v4.12", "branch_ids": ["br_…", "…"],
 "fork_latency_ms": 0.42, "dirty_ram_bytes": 0, "state_hash": "8f4343…"}
```

The coordinator MUST check three things: the returned ids equal the minted ids; every branch's `state_hash` equals the source's state hash as tracked by the coordinator; and `root_snapshot_id` matches. Any mismatch is a protocol fault.

### 4.5. `SRP_STEP` (Coordinator → Provider)

```json
{
  "request_id": "req_6c1d…",
  "branch_id": "br_001",
  "action": {"command": "apply_tactic", "payload": {"tactic": "simp [Nat.add_comm]"}},
  "timeout_ms": 5000
}
```

`request_id` is chosen by the coordinator and MUST be unique. `timeout_ms` is a hard deadline: suites that execute agent code kill the sandbox at the deadline (SRP-003 §3).

**Response (`SRP_STEP_RESULT`):**
```json
{
  "request_id": "req_6c1d…",
  "branch_id": "br_001",
  "observation": {"stdout": "Goals accomplished!", "stderr": "", "exit_code": 0, "structured_data": {}},
  "reward": 1.0,
  "terminated": true,
  "truncated": false,
  "metrics": {"exec_time_ms": 12.4, "dirty_pages": 14, "dirty_bytes": 57344,
              "total_branch_ram_bytes": 61440, "step_dirty_pages": 2},
  "receipt": {
    "node_id": "srp_node_9f8a7b6c",
    "branch_id": "br_001",
    "request_id": "req_6c1d…",
    "root_snapshot_id": "snap_lean4_mathlib_v4.12",
    "step_index": 3,
    "parent_state_hash": "8f4343…",
    "action_hash": "3a1f9c…",
    "next_state_hash": "e9b211…",
    "dirty_page_merkle_root": "c0ffee…",
    "stdout_hash": "51d0a7…",
    "reward": 1.0,
    "terminated": true,
    "truncated": false,
    "observation_hash": "77ab…",
    "step_dirty_pages": 2,
    "timeout_ms": 5000,
    "signature_scheme": "ed25519",
    "signature": "<64-byte Ed25519 signature, hex>"
  }
}
```

`step_index` starts at 1 for the first step on each branch and increments by one. The receipt (V3) signs the whole observation, the billed metrics and the timeout. The digest and checks are defined in SRP-003 §2.1. `reward` MUST be finite.

### 4.6. `SRP_EVICT` (Coordinator → Provider)

```json
{"snapshot_ids": ["snap_…"], "branch_ids": ["br_…"]}
```

Drops the listed branches and snapshots and releases their page references; pages no longer referenced by anything are freed. Evicting a snapshot that still has branches either evicts them too or is refused, at the coordinator's choice; a refused eviction leaves the snapshot pinned and routable. An in-flight step on an evicted branch completes before the branch is dropped.

### 4.7. `SRP_MEMORY_PING` / `SRP_MEMORY_PING_RESPONSE`

A chained challenge with `sample_page_count` sequential lookups, at most 65,536. The response carries the flattened lookup indices, every page hash, and the final chain digest (SRP-003 §2.3).

### 4.8. `SRP_FRAUD_PROOF`

A slashable `FraudProof` is self-contained. It carries the node-signed receipt, the node's public key, the root snapshot id and content hash, the full lineage (actions and timeouts) and the runtime profile. Anyone can replay it to confirm the fraud (SRP-003 §2.4).

---

## 5. Authenticated Transport (`srp/transport/http.py`)

Nodes on other hosts are served by `NodeServer` and reached through `RemoteNode`. Commands are POSTed to `/srp/v1` as JSON-RPC envelopes:

```json
{"jsonrpc": "2.0", "id": "…", "method": "node.step", "params": {…},
 "auth": {"coordinator": "<ed25519 pubkey>", "ts": 1731234567.1, "nonce": "…", "sig": "…"}}
```

* **Commands.** `sig` is an Ed25519 signature by the coordinator over `"SRP_CMD_V1|" + canonical_json({node_id, method, params, id, ts, nonce})`. A node only accepts its configured coordinator key (otherwise 401), timestamps within ±60 s (otherwise 401), and single-use nonces (a replay gets 409).
* **Responses.** Every response, errors included, is signed by the node over `"SRP_RESP_V1|" + id + "|" + canonical_json({result|error})`.
* **Errors.** Only an allow-listed set of error types crosses the wire.
* **Deadlines and TLS.** Clients enforce a deadline. TLS or mTLS is enabled by passing an `ssl.SSLContext` to both sides. The server runs each TLS handshake in its per-connection worker thread under `connection_timeout_s` (default 30 s), so a client that connects and never handshakes cannot stall other requests.
