# Roadmap

SRP is maintained by one person. The order below is the order of work; there are no dates. Items under "Planned, not scheduled" will wait until the economics analysis shows where SRP is worth using, or until someone wants to collaborate on them.

| Version | Status | Scope |
|---|---|---|
| **v0.5** | Current (alpha) | Four specs, reference implementation, four simulated environment suites, end-to-end demo, test suite. |
| **v0.6** | Next | Economics and latency analysis. Reproducible benchmarks for step latency, simulated network round-trip time, OS-level memory saved by Copy-on-Write, and replay-audit overhead. A written verdict in `docs/ECONOMICS.md` on when SRP beats renting datacenter RAM and when it does not. README claims replaced by measured numbers. |
| **v0.7** | After v0.6 | Security hardening. Property-based tests for wire-message validation, a sandbox escape-attempt suite, dependency and static-analysis checks in CI, and a security review guide. |
| **v1.0** | Later | Community security review complete and its findings addressed. Permissionless testnet. |

## Planned, not scheduled

- Container-backed environment runner, as an opt-in alternative to the simulated Python environments.
- An adapter for one established RL training stack (verl is the likely first target), with a small end-to-end GRPO example.
- A real Lean 4 or browser-backed environment.

## What v0.5 is not

- The environments are small simulations (a Lean-style tactic checker, a DOM state machine, a CAD geometry verifier, a sandboxed code grader). They are not Lean 4, a browser, or production containers.
- The capacity and savings figures in the README are estimates and worked examples until v0.6 measures them.
- The protocol has had no external security review. Do not run it permissionlessly.

If you want to help with any of this, see [CONTRIBUTING.md](CONTRIBUTING.md).
