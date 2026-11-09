# SRP-002: Copy-on-Write (CoW) Volatile RAM Arena Specification

**Status:** Draft Standard (v0.1.0)  
**Category:** Memory Management & Hardware Protection  
**License:** MIT / Public Domain (CC0)

---

## 1. Zero-Disk-Wear Guarantee

A foundational ethical commitment of the Share RAM Protocol is **Zero Persistent Storage Degradation**. Consumer NVMe/SSD drives have finite Terabytes Written (TBW) endurance ratings. Traditional distributed compute frameworks write container layers to disk, silently wearing out volunteer hardware.

SRP enforces a strict **Volatile Memory Only** rule:
1. All base snapshots, CoW page tables, file overlays, and stdout buffers reside strictly in volatile RAM (`RAMPageArena`, `mmap(MAP_ANONYMOUS)`, or `tmpfs` with `noswap`).
2. When the node daemon exits or evicts a snapshot, zero artifacts remain on disk.
3. The node enforces a hard user-configured ceiling (`max_ram_bytes`) and refuses allocations that would trigger host OS swap-to-disk.

---

## 2. Page-Granular Copy-on-Write Architecture

### 2.1. Page Size and Arena Layout
The `RAMArena` divides allocated memory into fixed-size **4096-byte (4 KB) pages** (matching standard x86_64 and ARM64 virtual memory page frames).

* **Immutable Base Frame ($S_0$):** When a snapshot is pinned, its Virtual File System (VFS) and linear memory state are chunked into 4 KB content-addressed pages stored in the shared page pool.
* **Branch Page Table ($B_k$):** When `SRP_FORK` is called on $S_0$ (or on an existing branch $B_j$), the new branch $B_k$ receives a lightweight **shallow copy of the page-index map** referencing the parent's immutable page frames.
  $$\text{MemoryOverhead}(\text{Fork}) = \mathcal{O}(P_{\text{ptrs}}) \ll \mathcal{O}(\text{SnapshotSize})$$
* **Write Interception (Copy-on-Write Fault):** When an RL step modifies bytes in file $f$ or memory offset $x$:
  1. The arena computes the affected 4 KB page indices: $p_i = \lfloor x / 4096 \rfloor$.
  2. Only those mutated 4 KB pages are allocated from the free RAM pool and updated in $B_k$'s page table.
  3. All unmodified pages remain shared with $S_0$ at zero extra RAM cost.

---

## 3. Multi-Turn Tree Rollouts (GRPO & MCTS)

Because `SRP_FORK` works identically on **base snapshots** and **intermediate branches**, SRP natively accelerates tree-based RL algorithms:

```text
Base Snapshot S0 (500 MB in RAM)
 ├── Branch B1 (+12 KB dirty pages) ──> Action 1a
 │    ├── Sub-branch B1_1 (+8 KB dirty pages) ──> Action 2a (Reward: +1.0)
 │    └── Sub-branch B1_2 (+16 KB dirty pages) ──> Action 2b (Reward: 0.0)
 └── Branch B2 (+16 KB dirty pages) ──> Action 1b (Reward: +0.5)
```

Total physical RAM consumed across 1 base snapshot + 4 active rollout states:
$$500\text{ MB} + 12\text{ KB} + 8\text{ KB} + 16\text{ KB} + 16\text{ KB} = 500.052\text{ MB}$$
Compared to $5 \times 500\text{ MB} = 2,500\text{ MB}$ in traditional container architectures (**80%+ RAM savings at 4 branches; 98%+ RAM savings at 64 branches**).
