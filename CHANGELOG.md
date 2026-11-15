# Changelog

All notable changes to SRP. Versions follow the protocol version (`PROTOCOL_VERSION`); while SRP is alpha, any minor version may break compatibility.

## 0.7.0 (2026-11-15)

Includes the v0.6 work (benchmarks, economics analysis and the fixes they pointed to) and the v0.7 security hardening. There was no separate 0.6.0 release.

### Breaking

- **Protocol version 0.7.0.** Coordinators refuse nodes that report another version, and the wire codec rejects frames with another `srp_version`. This matters beyond the version string: the sandbox policy below changed, so a 0.5 node and a 0.7 auditor could disagree about which agent code is valid.
- **Sandbox policy is stricter.** Agent and test code may no longer assign or delete attributes (`x.a = ...`, `del x.a`), and `.format` / `.format_map` may only be called on a string literal whose fields pass the attribute checks. Snapshot test suites that relied on either need updating.
- **Example settlement rates changed.** `FiatAndApiCreditLedger` and `TokenEscrowLedger` now default to 0.002 per GB-hour, 0.000001 per step and 0 per dirty MB (were 0.04–0.05, 0.0005–0.001 and 0.001). Pass rates explicitly if you depended on the old defaults.

### Security

- Closed a grading bypass: a solution could overwrite methods on the replacement `str` class shared with the pinned tests (`str.isdigit = lambda s: True`) and make a failing test pass.
- Closed an introspection hole: a format string built at run time could read private attributes past the static `__` checks.
- Added `tests/test_srp_sandbox_escapes.py`: 60 documented escape attempts, each labelled with the layer that stops it.
- Added property-based tests for wire validation and the transport handlers (`tests/test_srp_wire_properties.py`, Hypothesis).
- CI runs `bandit` (medium severity and above) and `pip-audit`.
- Added [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md), a guide for reviewers.

### Added

- `python -m benchmarks`: step latency, throughput under simulated network round-trip times, OS-level memory saved by Copy-on-Write, and replay-audit overhead. Results in `benchmarks/results/`.
- [docs/ECONOMICS.md](docs/ECONOMICS.md): when SRP beats renting datacenter RAM, and when it does not. Verdict: not for paid capacity; credible for donated capacity and latency-tolerant multi-turn workloads.
- `SRPCoordinator(rewarded_audit_rate=...)`: audit rewarded and terminal steps with a given probability. The default (1.0) keeps auditing every one; 0.1 cut duplicated audit work from 100% to 13–20% in the benchmarks, at the cost described in SRP-003 §2.2. Reported in `cluster_telemetry()`.
- `RemoteNode.close()`; `RemoteNode.url` can be changed and drops pooled connections.
- `CHANGELOG.md`, `ROADMAP.md`, `CONTRIBUTING.md` and a CI workflow (Linux and Windows, Python 3.10 and 3.12).

### Changed

- **Persistent connections.** `RemoteNode` pools HTTP/1.1 keep-alive connections: one network round trip per call instead of two. A stale connection is retried once with the identical signed frame, so a command can never run twice.
- `NodeServer`: listen backlog 128 (was 5), which removes 1-second stalls under concurrent load; `TCP_NODELAY` on connections; connections close after any rejected frame and when the server stops.
- A pinned snapshot no longer keeps its manifest, which held a second copy of every byte: memory per pinned snapshot fell from 2.1× to 1.15× its size.
- README claims are labelled as measured or as estimates, and the README states where SRP fits.

## 0.5.0 and earlier

See the git history (`e4ecc00` for 0.5.0, `2eaec30` for 0.4.0).
