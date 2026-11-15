# Roadmap

SRP is maintained by one person. The order below is the order of work; there are no dates. Items under "Planned, not scheduled" will wait until there is a clear use for them, or until someone wants to collaborate on them.

| Version | Status | Scope |
|---|---|---|
| **v0.5** | Released (alpha) | Four specs, reference implementation, four simulated environment suites, end-to-end demo, test suite. |
| **v0.6** | In progress | Reproducible benchmarks (`python -m benchmarks`) and a written verdict in [docs/ECONOMICS.md](docs/ECONOMICS.md). Fixes 1–3 below are done and re-measured; 4 and 5 remain. |
| **v0.7** | After v0.6 | Security hardening. Property-based tests for wire-message validation, a sandbox escape-attempt suite, dependency and static-analysis checks in CI, and a security review guide. |
| **v1.0** | Later | Community security review complete and its findings addressed. Permissionless testnet. |

## v0.6 fixes found by the benchmarks

1. ~~Persistent connections in the HTTP transport.~~ Done: one round trip per call instead of two.
2. ~~A larger listen queue in `NodeServer`.~~ Done: no more 1-second stalls under concurrent load.
3. ~~Release snapshot file contents after pinning.~~ Done: a pinned snapshot costs 1.15× its size instead of 2.1×.
4. An audit policy that does not replay every rewarded episode (needs a change to SRP-003, since it trades verification strength for cost).
5. Example settlement rates calibrated to datacenter RAM prices.

## Planned, not scheduled

- Container-backed environment runner, as an opt-in alternative to the simulated Python environments.
- An adapter for one established RL training stack (verl is the likely first target), with a small end-to-end GRPO example.
- A real Lean 4 or browser-backed environment.

## What SRP is not (yet)

- The environments are small simulations (a Lean-style tactic checker, a DOM state machine, a CAD geometry verifier, a sandboxed code grader). They are not Lean 4, a browser, or production containers.
- SRP is not cheaper than renting datacenter RAM for paid capacity, and is not suited to tight environment loops over the internet. See [docs/ECONOMICS.md](docs/ECONOMICS.md).
- The protocol has had no external security review. Do not run it permissionlessly.

If you want to help with any of this, see [CONTRIBUTING.md](CONTRIBUTING.md).
