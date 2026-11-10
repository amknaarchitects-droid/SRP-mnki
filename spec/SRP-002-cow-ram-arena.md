# SRP-002: Copy-on-Write (CoW) Volatile RAM Arena Specification

**Status:** Draft Standard (v0.3.0)  
**Category:** Memory Management & Hardware Protection  
**License:** MIT / Public Domain (CC0)

---

## 1. Zero-Disk-Wear Guarantee

A foundational commitment of the Share RAM Protocol is **zero persistent storage degradation**. Consumer NVMe/SSD drives have finite Terabytes Written (TBW) endurance.

SRP enforces a **volatile-memory-only** rule:
1. All base snapshots, CoW page tables, file overlays, ballast and stdout buffers reside in process memory. The reference arena never opens a file for writing.
2. Agent code executes in a sandbox child process that, on POSIX, runs with `RLIMIT_FSIZE = 0` (any file write fails) and receives its inputs over a pipe rather than via temporary files.
3. When the node daemon exits or evicts a snapshot, no artifacts remain on disk.
4. The node enforces a hard user-configured ceiling (`capacity_mb`) and refuses any allocation that would exceed it.

**Honest limits.** A managed runtime cannot guarantee that released memory is zeroed, nor that the OS never pages the process out. Nodes that need those properties SHOULD run with swap disabled (or `mlock`ed arenas) and use a runtime that scrubs freed pages. The ceiling counts page data plus a conservative estimate of bookkeeping (§2.5), not total process RSS.

---

## 2. Page-Granular Copy-on-Write Architecture

### 2.1. Pages
The arena divides memory into fixed-size **4096-byte pages**, content-addressed by `SHA-256(page_bytes)`. Each file is split into `max(1, ceil(len/4096))` pages; the final page is zero-padded and the file's true `byte_length` is recorded.

### 2.2. Snapshots and branches
* **Immutable base frame ($S_0$):** a pinned snapshot's pages live in the shared base pool, reference-counted per snapshot.
* **Branch page table ($B_k$):** `SRP_FORK` gives a branch a shallow copy of its source's file table. Forking costs $\mathcal{O}(\#\text{files} + \#\text{dirty pages})$, independent of snapshot size.
* **Write (CoW fault):** rewriting file $f$ re-chunks only $f$. Pages identical to the branch's root snapshot keep pointing at the base pool; every other page is held by the branch in the dirty pool.

### 2.3. Ownership invariant
A branch holds its own dirty-pool reference to **every page in its file table that is not part of its own root snapshot**, even when an unrelated snapshot happens to pin identical bytes. The base and dirty pools are reference-counted independently, so evicting any snapshot other than a branch's root can never strand that branch. A page present in both pools is stored once but charged twice against the ceiling (conservative).

### 2.4. State hash
For a file table $T$:

$$\text{FileDigest}(p) = \text{SHA256}\big(p \,\|\, \texttt{:} \,\|\, \text{len}(p) \,\|\, \texttt{:} \,\|\, \text{join}(\text{PageHashes}(p), \texttt{,})\big)$$

$$\text{StateHash}(T) = \text{MerkleRoot}\big([\text{FileDigest}(p) \text{ for } p \in \text{sorted}(T)]\big)$$

`MerkleRoot` hashes leaves as `SHA256("leaf:"‖h)`, internal nodes as `SHA256("node:"‖l‖":"‖r)`, promotes an odd node as `SHA256("odd:"‖h)`, and maps the empty list to `SHA256("SRP_EMPTY_MERKLE_TREE")`. The state hash is a pure function of the branch's contents, so two honest executions of the same lineage produce the same hash; the transition chain is carried by receipts (SRP-003 §2.1). A snapshot's `content_merkle_root` is `StateHash` of its initial file table. Per-file digests are cached, so a write costs $\mathcal{O}(|f| + \#\text{files})$.

### 2.5. Capacity accounting
`committed = base + dirty + ballast page bytes + metadata estimate`. The metadata estimate charges per pinned snapshot, per branch, per file entry, per dirty-page reference and per page-table entry, and the charge is refunded on eviction. Pins, ballast, forks and writes that would exceed `capacity_mb` raise an error **before** any state changes.

### 2.6. Concurrency
Each branch has a step lock, and the arena has a global lock. Lock order is always *branch step lock → arena lock*.
* **Steps** on one branch are serialised.
* **Forks:** forking a branch waits for any in-flight step on it.
* **Branch eviction** waits for an in-flight step, then marks the branch dead so no later write can leak pages.
* **Snapshot eviction** is single-owner: concurrent calls for the same snapshot wait and then return 0. While a snapshot is being evicted, pins, ballast pins and forks (of the snapshot *or of its branches*) are refused.
* **Branch ids** come from the coordinator (`SRP_FORK.branch_ids`), and ids already in use are refused.

### 2.7. TTL
Branches forked with `ttl_seconds` are evicted once expired. Expiry is checked lazily on access (re-checked under the step lock), and eagerly by `reap_expired()`, which only scans branches that have a TTL.

---

## 3. Multi-Turn Tree Rollouts (GRPO & MCTS)

Because `SRP_FORK` works identically on base snapshots and intermediate branches, SRP natively supports tree-structured RL:

```text
Base Snapshot S0 (500 MB in RAM)
 ├── Branch B1 (+12 KB dirty pages) ──> Action 1a
 │    ├── Sub-branch B1_1 (+8 KB) ──> Action 2a (Reward: +1.0)
 │    └── Sub-branch B1_2 (+16 KB) ──> Action 2b (Reward: 0.0)
 └── Branch B2 (+16 KB dirty pages) ──> Action 1b (Reward: +0.5)
```

Physical page RAM for 1 base snapshot + 4 rollout states: $500\text{ MB} + 52\text{ KB}$ (plus small per-branch metadata), versus $5 \times 500\text{ MB}$ for independent containers.
