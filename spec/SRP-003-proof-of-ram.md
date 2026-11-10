# SRP-003: Proof-of-Honest-RAM (PoHR) & Verification Specification

**Status:** Draft Standard (v0.4.0)  
**Category:** Security & Cryptographic Verification  
**License:** MIT / Public Domain (CC0)

---

## 1. Threat Model

**Untrusted provider nodes** may attempt:
1. **Lazy spoofing / reward poisoning:** fabricated rewards, observations or billed metrics.
2. **Residency fraud:** claiming RAM they don't hold, serving pages from swap or regenerating them on demand.
3. **Identity attacks:** impersonation, receipt replay, branch-id hijacking, and escaping penalties by re-registering.
4. **Griefing the verifier:** making an audit fail by itself so that a different node gets framed.

**Untrusted agents** (the policy being trained) may attempt reward hacking or sandbox escape.

**Untrusted networks:** an attacker may read, replay, drop or alter frames.

**The coordinator** is trusted by the trainer that runs it, but not by nodes. It must not be able to forge receipts, and a slash must be backed by evidence that anyone can check.

---

## 2. Verification Layers

### 2.1. Layer 1: Signed, bound receipts (V3)

The node signs, with Ed25519:

```
digest = SHA256("SRP_RECEIPT_V3|" node_id "|" branch_id "|" request_id "|" root_snapshot_id "|"
                step_index "|" parent_state_hash "|" action_hash "|" next_state_hash "|"
                dirty_page_merkle_root "|" stdout_hash "|" reward(%.8f, finite) "|" terminated "|"
                truncated "|" observation_hash "|" step_dirty_pages "|" timeout_ms)
observation_hash = SHA256(canonical_json({stdout, stderr, exit_code, structured_data, truncated}))
```

So every value a trainer consumes or the ledger bills on is signed. The coordinator:
* mints `request_id` and the branch ids, and rejects fork replies whose ids differ;
* tracks each branch's state hash, step index, root and lineage itself;
* rejects any receipt whose signature, ids, step index, parent hash, action hash, timeout, reward (finite, exact), flags, observation hash or metrics differ from what it dispatched or received.

Steps on one branch are serialised, so honest concurrent use never breaks the chain.

### 2.2. Layer 2: Blind, incremental, confirmed replay audits

**Runtime profiles.** A suite is deterministic only for a fixed runtime profile: `cpython-<major.minor>-<str hash algorithm>-<os>`. Within a profile the reference sandbox fixes `PYTHONHASHSEED`, disables ASLR on Linux, and scrubs memory addresses from every text path. Nodes advertise their profile, and the coordinator only accepts a node if it has an **auditor** (a trusted node it controls) with the same profile.

**Audits.**
* **Lineage.** Each branch keeps an immutable lineage of committed steps: the action, its timeout and the node's signed receipt. Each step's digest is computed over the previous digest, the timeout and the action.
* **Which steps.** The coordinator audits a random fraction (`audit_rate`, using a CSPRNG and decided *after* the node answers). It always audits steps that are rewarded, terminal or report a timeout.
* **Incremental replay.** The auditor resumes from its nearest cached checkpoint (an LRU of CoW branches keyed by lineage digest). It re-executes every committed step since that checkpoint and compares each one's signed outcome, then executes the new step. A lie on an unaudited step is therefore caught by any later audit of that branch. Cost per audit is O(steps since the last checkpoint), not O(rollout length).
* **Confirmation.** A mismatch only counts as fraud if `audit_confirm_runs` further trusted runs all agree with each other and contradict the node. If the auditor itself is nondeterministic, the audit is *inconclusive* and nobody is penalised.
* **Coordinator failures.** If the coordinator's own audit fails for any reason (out of memory, a bug, an interrupt), the audit is inconclusive and the verified receipt is still committed. The branch is never left desynchronised, and the node is never framed.

**Timeouts.** Agent code is limited by deterministic *fuel* (SRP §3), so a run either finishes or exhausts its fuel identically on every machine. Wall-clock time is only a backstop, set at 2× the timeout + 1 s.
* A step that hits the backstop earns nothing, and its branch is closed.
* Such a step is always audited. If the auditor finishes it in under 25% of the backstop, the node gets a *strike*. `timeout_strike_limit` strikes means quarantine.
* Claiming timeouts therefore gains nothing and cannot hide a branch from audits.

**Canaries.** Canary tasks run through the ordinary fork/step path with audits still eligible. Each canary is sent to a random node, in random order, and optionally after a prefix of real committed actions, so it can sit at any depth. When the expected values are not supplied, ground truth comes from the auditor. With `canary_rate > 0`, rounds are scheduled in the background.

### 2.3. Layer 3: Chained residency proofs (`srp/protocol/residency.py`)

**Sequential ballast.** Each pin comes with a node-unique seed, derived as `HMAC(master_secret, node | pubkey | snapshot)`. The node expands it into `max(min_ballast_pages, ceil(ballast_ratio × distinct snapshot pages))` pages, where

```
page_i = SHAKE256("SRP_BALLAST_V2|" seed "|" i "|" page_{i-1})[:4096]
```

Page *i* cannot be computed without page *i-1*. A node that keeps only every *m*-th page must recompute about *m/2* pages per lookup.

**Chained challenge.** For `rounds` lookups:
1. The node reads the page selected by the current state.
2. It hashes that page.
3. The page hash advances the state, which selects the next lookup.

Lookups are therefore strictly sequential: no prefetching or parallel I/O is possible. The node returns every page hash. The coordinator re-derives the whole index chain, checks every snapshot lookup against the manifest, and spot-checks `ping_spot_checks` ballast lookups using its own sparse checkpoints.

**Timing.** Before each challenge, the coordinator measures a zero-lookup round trip.

```
per-lookup µs = (challenge ms − baseline ms) × 1000 / rounds
```

The node passes when the median over `ping_repeats` is at most `max_lookup_us` (default 60). DRAM lookups cost microseconds; swap costs about 100 µs per random 4 KB read; recomputing from checkpoints costs hundreds of µs. Summed over hundreds of lookups, these gaps are far above WAN jitter.

**What is paid.** Snapshot pages are public, so only ballast bytes (node-unique and provable) earn RAM-lease value (SRP-004 §2). Snapshot residency itself is enforced indirectly: a node can't execute steps without the snapshot.

### 2.4. Fraud, faults and appeals

| Kind | Evidence | Consequence |
|---|---|---|
| `replay_mismatch`, `canary_mismatch` | node-signed receipt + root snapshot id + content hash + full lineage (actions and timeouts) + runtime profile | **slashable**, quarantine |
| `protocol_fault` (bad signature, inconsistent receipt, fork-id mismatch, repeated false timeouts) | not attributable to a third party | quarantine only, **no slash** |

* **Checking a proof.** `verify_fraud_proof_by_replay(proof, manifest)` lets anyone with the same runtime profile confirm a slashable proof. `SettlementProvider.record_canary_failure` refuses any proof that is not self-contained.
* **Quarantine.** It binds both the `node_id` and the public key, refuses residency payments, and is persisted (`state_path`) together with identities, strikes, fraud evidence, the ballast master secret and the coordinator key.
* **Appeals.** `appeal_fraud(i)` re-runs the proof's lineage. If the fraud is not confirmed, the node is reinstated and the slash is refunded.

---

## 3. Agent-Code Sandbox (`srp/envs/sandbox.py`, `srp/envs/fuel.py`)

1. **Static policy.** No imports, async, classes, `global`/`nonlocal` or bare `except:`. No `__dunder__` names, definitions, arguments or string constants. No `_private` attributes, and no frame/code/traceback introspection attributes.
2. **Fuel.** Loops, calls, lambdas, comprehension items and iteration-consuming builtins cost fuel. `**`, `*` and `<<` are guarded against huge integer or sequence results. Fuel equals `timeout_ms × 2000`, and running out raises the uncatchable `FuelExhausted`.
3. **Process isolation.** Each run is a fresh `python -s -S` (plus `-P` on 3.11+) with a fully controlled environment, minimal builtins, and inputs passed over stdin. `-I` is deliberately not used: it implies `-E`, which would ignore `PYTHONHASHSEED=0` and randomise string hashing per run. The child strips `''`/`.` from `sys.path` before its first import, so modules planted in the working directory are never loaded. The pinned tests run in their **own namespace** and see only the solution's public, non-builtin names, so a solution cannot shadow `sum`, `len` and the like.
4. **Audit hook (every OS).** Once armed, every CPython audit event is refused except executing the two pre-compiled code objects. That covers imports, `open`, sockets, subprocess/`os.*`, ctypes, `sys._getframe`, and restricted attribute reads such as `gi_frame`, `tb_frame` and `__code__`. The hook still holds if layer 1 is bypassed (tested).
5. **OS isolation.**
   * **Linux:**
     * a user + network namespace with no interfaces;
     * ASLR disabled;
     * `RLIMIT_AS`, `CPU`, `FSIZE=0`, `NPROC=0`, `NOFILE` and `CORE` limits;
     * a seccomp-BPF filter for **x86_64 and aarch64** (any other ABI on the same kernel, such as x32 or compat arm32, is killed) returning `EPERM` for: network calls, process creation, `exec`, `ptrace`, namespace/mount changes, kernel attack-surface calls, and write-capable `open`/rename/unlink/mkdir/chmod/truncate.
   * **Windows:** the child starts suspended, joins a kill-on-close Job Object (memory cap, CPU-time cap, single process), then resumes. Network is refused by layer 4 only.
6. **Hidden grading inputs.** The agent cannot `read_file` (or overwrite) the pinned test file, the run log or the property salt.
7. **Hash-order determinism.** Set iteration order follows element hashes, and for functions, types, exceptions, iterators, NaN (and `None` before 3.12) the hash is a memory address. Every way agent code can build or grow a set (literals, comprehensions, `set()`/`frozenset()`, `add`/`update`/`union`/..., `| & ^ -` and their augmented forms, including on dict views) goes through deterministic set types that raise `TypeError` for such elements. Sets of numbers, strings, bytes, ranges and tuples/frozensets of those behave as usual.
8. **Property-based grading.** Pinned tests may call `srp_randint(lo, hi)`, `srp_choice(seq)` and `srp_random()` (splitmix64, bit-exact everywhere). The seed is `SHA256(tests ‖ hidden salt ‖ path ‖ submitted code)` (length-prefixed, `.srp_property_salt` in the snapshot), so the agent cannot know the inputs before it submits, every submission gets fresh inputs, and replay audits reproduce them exactly. The helpers exist only in the test namespace.

Nodes advertise `sandbox_isolation` (`isolation_report()`). A coordinator can require kernel-level isolation (`require_kernel_isolation=True`), which today means Linux nodes (x86_64 or aarch64).

## 4. Verifier Reward Integrity

* Completion rewards are paid once, and partial-credit shaping only pays on strict improvement.
* CAD uses true constructive solid geometry: exact for boxes, adaptively sampled for curved primitives. A scene with no design spec earns no reward.
* Reward values must be finite, and a non-finite verifier output is coerced to 0.

## 5. Residual Risks (honest limits)

* **Determinism across profiles:** steps cannot be audited across profiles, which is why the coordinator refuses such nodes. Within a profile, address-dependent set ordering is now refused at runtime (§3.7). Dict order is insertion order and is unaffected. Remaining nondeterminism would need a CPython bug, and confirmation runs still turn it into an inconclusive result rather than fraud.
* **Grading quality:** seeded property tests (§3.8) defeat special-casing of visible examples, but only if snapshot authors write them. A weak test suite is still a weak reward signal.
* **Sandbox:** the sandbox is not a hypervisor. Windows nodes have no kernel network filter (an AppContainer launch would need ACL changes on the Python install, so it is left to operators), and CPython memory-safety bugs are out of scope. Permissionless networks should require Linux kernel isolation, or back `container_tmpfs` with gVisor, Firecracker or WASM.
* **Residency:** the challenge is statistical. It proves possession of node-unique ballast at DRAM-like latency, not that snapshot pages are never swapped.
