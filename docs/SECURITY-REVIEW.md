# Security Review Guide

This guide is for anyone reviewing SRP's security: what is in scope, what the design claims, where each claim lives in the code, and what is already known to be weak. SRP has had **no independent security review**. The v1.0 gate on the [roadmap](../ROADMAP.md) is a community review whose findings have been addressed. Until then, do not run SRP permissionlessly.

Please report vulnerabilities privately through GitHub's private vulnerability reporting (Security tab, "Report a vulnerability"), not in a public issue.

## 1. Scope

In scope:

- The reference implementation in `srp/`, and the four specifications in `spec/`, which are normative.
- The HTTP transport between a coordinator and provider nodes.
- The code sandbox that grades untrusted agent code.

Out of scope:

- The four bundled environment suites as *environments*: they are small simulations, not Lean 4, a browser or production containers. Their reward logic is in scope (it decides what is paid and what a trainer learns).
- CPython memory-safety bugs, and the operating system kernel.
- Settlement backends beyond the reference ledgers (Stripe, chains, claim contracts).

## 2. Threat model in one paragraph

Provider nodes are untrusted: they may fabricate rewards, observations and billed metrics, claim RAM they do not hold, impersonate other nodes, or try to get an honest node framed. Agent code (the policy being trained) is untrusted and may try to escape the sandbox or fake a passing grade. The network is untrusted. The coordinator is trusted by the trainer that runs it but not by nodes, so it must not be able to forge receipts, and every slash must carry evidence anyone can check. The full model is [SRP-003 §1](../spec/SRP-003-proof-of-ram.md).

## 3. Where each claim lives

| Claim | Spec | Code |
|---|---|---|
| Frames are strictly validated; only `WireError` escapes the decoder | SRP-001 | `srp/protocol/wire.py` (`decode_message`, `decode_body`, `loads_strict`) |
| Commands come only from the configured coordinator key, are fresh and single-use; responses are signed | SRP-001 | `srp/transport/http.py` (`NodeServer._handle`, `RemoteNode._call`, `RemoteNode._post`) |
| A retried request never executes twice | SRP-001 | `RemoteNode._post` re-sends the identical frame; `_NonceCache` rejects the copy |
| Ed25519 signing and verification | SRP-001, SRP-003 §2.1 | `srp/protocol/crypto.py` (`cryptography` when installed, pure-Python RFC 8032 fallback otherwise) |
| Receipts are bound to request, branch, step index, parent hash and timeout | SRP-003 §2.1 | `srp/protocol/messages.py` (`ExecutionReceipt`), `SRPCoordinator._layer1` in `srp/coordinator/server.py` |
| Replay audits are blind, incremental and confirmed before anyone is penalised | SRP-003 §2.2 | `SRPCoordinator._dispatch`, `SRPCoordinator._audit` |
| Fraud proofs are self-contained and third-party checkable | SRP-003 §2.4 | `SRPCoordinator._record_fraud`, `verify_fraud_proof_by_replay` |
| RAM residency is proven over node-unique ballast | SRP-003 §2.3 | `srp/protocol/residency.py`, `SRPCoordinator.verify_node_ram_residency` |
| Agent code cannot escape the sandbox or fake a grade | SRP-003 §3 | `srp/envs/sandbox.py` (`validate_code`, `prepare_source`, `_CHILD_PROGRAM`, `seccomp_program`, `_linux_preexec`, `_WindowsJob`), `srp/envs/fuel.py` |
| Snapshot pages are copy-on-write and never written to disk | SRP-002 | `srp/node/ram_arena.py` |
| Stake, slashing, unbonding and payouts | SRP-004 | `srp/settlement/base.py` (`BaseConfigurableLedger`) |
| Quarantine and coordinator state survive restarts | SRP-003, SRP-004 | `SRPCoordinator.save_state`, `SRPCoordinator._load_state` |

## 4. Known limits

These are deliberate or not yet fixed. A review that confirms or sharpens them is still useful.

- **Sandbox is not a hypervisor.** It is a static AST policy, deterministic fuel, a CPython audit hook, restricted builtins and process isolation, plus seccomp-BPF, a network namespace and rlimits on Linux. Windows nodes have no kernel network filter; set `require_kernel_isolation=True` to admit only Linux nodes. Production deployments should back environments with gVisor, Firecracker or WASM.
- **Sampled reward audits.** With `rewarded_audit_rate < 1`, some fabricated rewards reach the trainer before a cheating node is caught, and a lie on an unaudited final step is never re-checked. The default (1.0) audits every rewarded step.
- **Determinism holds only within a runtime profile** (Python version, hash algorithm, OS, CPU architecture). Nodes without a matching auditor are refused.
- **Residency challenges are statistical.** They prove possession of node-unique ballast at DRAM-like latency, not that snapshot pages are never swapped.
- **Grading is only as strong as the pinned tests.** Seeded property helpers stop special-casing of visible examples only if snapshot authors use them.
- **Pure-Python Ed25519 fallback** is correct but not constant-time. Install the `crypto` extra in any real deployment.
- **The coordinator is a single trusted party** that holds the master secret and its signing key in its state file. Protect that file, or supply both from a KMS.
- **The format-string and attribute-assignment rules are recent** (v0.7, found by the escape suite). Other ways to reach shared objects from agent code are worth a fresh look.

Each of these appears in [SRP-003 §5](../spec/SRP-003-proof-of-ram.md) or the README's security table.

## 5. What is already tested

| Area | Tests |
|---|---|
| Sandbox escape attempts, each labelled with the layer that stops it | `tests/test_srp_sandbox_escapes.py` |
| Kernel layers on Linux (seccomp, network namespace) | `tests/test_srp_security.py` (`test_S1_linux_kernel_layers_block_network_process_and_writes`), `tests/test_srp_hardening.py` |
| Wire validation, property-based (Hypothesis): round trips, only `WireError` escapes, bounds, nesting, transport handlers | `tests/test_srp_wire_properties.py` |
| Signed transport, replay rejection, TLS and mTLS | `tests/test_srp_security.py`, `tests/test_srp_hardening.py`, `tests/test_srp_v06_fixes.py` |
| Receipt binding, audits, fraud proofs, slashing and appeals | `tests/test_srp_security.py`, `tests/test_srp_regressions.py` |
| Sampled reward audits, including a test showing an unsampled lie passing | `tests/test_srp_v06_fixes.py` |

CI runs every test on Linux and Windows (Python 3.10 and 3.12), plus `bandit` (medium severity and above) and `pip-audit` on a separate Linux job. Some kernel-level tests run only on Linux.

## 6. Running the checks yourself

```bash
pip install -e ".[crypto,dev,bench]" bandit pip-audit
```

```bash
python -m pytest -v -rs
```

```bash
python -m bandit -r srp -ll
```

```bash
python -m pip_audit --skip-editable
```

To search harder than CI does, raise `max_examples` in `tests/test_srp_wire_properties.py` (CI uses 150; a 3,000-example run found nothing at the time of writing).

`bandit` at low severity reports `try/except/pass` around background canaries and best-effort eviction, and two `assert` statements (a fixed-constant sanity check in Ed25519 setup and a type narrowing in the Gym bridge). These are deliberate.

## 7. Suggested order for a reviewer

1. `srp/envs/sandbox.py`: the largest attack surface, and the one where agent code runs.
2. `srp/transport/http.py` and `srp/protocol/wire.py`: everything a network attacker can reach.
3. `srp/coordinator/server.py`: audits, fraud proofs and slashing, where a bug could frame an honest node or let a cheater keep earning.
4. `srp/protocol/residency.py`: the statistical argument behind paying for RAM.
5. `srp/settlement/base.py`: arithmetic on stake and payouts.
