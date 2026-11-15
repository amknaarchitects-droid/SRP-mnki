# Contributing to SRP

Thanks for your interest. SRP is an alpha-stage public-good project with one maintainer, so small, focused contributions are the easiest to review.

## Setup

Requires Python 3.10 or newer.

```bash
git clone https://github.com/amknaarchitects-droid/SRP-mnki.git
cd SRP-mnki
pip install -e ".[crypto,dev]"
```

Run the tests and the end-to-end demo:

```bash
pytest
```

```bash
python -m srp.cli demo
```

Both must pass before you open a pull request. Some sandbox tests need Linux kernel features (seccomp-BPF, network namespaces) and are skipped on Windows and macOS; CI runs them on Linux.

## Where things live

- `spec/`: the four protocol specifications. They are the source of truth.
- `srp/protocol/`: messages, wire format, signatures, residency challenges.
- `srp/node/`: the provider node and the Copy-on-Write RAM arena.
- `srp/coordinator/`: routing, replay audits, canaries, fraud proofs.
- `srp/envs/`: the simulated environment suites and the code sandbox.
- `srp/settlement/`: settlement providers.
- `srp/transport/`: the signed HTTP transport.
- `benchmarks/`: reproducible measurements; analysed in `docs/ECONOMICS.md`.

## Rules

- **Specs and code stay in sync.** If you change protocol behavior, update the matching file in `spec/` in the same pull request.
- **Do not weaken a test to make it pass.** If behavior legitimately changes, update the test and say why.
- **Security fixes need a test** that fails without the fix. New sandbox escape ideas belong in `tests/test_srp_sandbox_escapes.py`, labelled with the layer expected to stop them.
- **No unmeasured claims.** Numbers in the README or docs must come from a reproducible benchmark (`python -m benchmarks`, see `benchmarks/`) or be labelled as estimates. If a change affects performance, rerun the benchmarks and commit the new `benchmarks/results/`.
- Match the style of the surrounding code. Type hints on public functions.

## AI-assisted contributions

This codebase was itself developed with AI coding assistance, and AI-assisted pull requests are welcome. You are responsible for what you submit: read it, understand it, and make sure the tests pass.

## Process

- For anything larger than a small fix, open an issue first so the approach can be agreed.
- Keep pull requests small and on one topic.
- Commit messages in the imperative mood ("Add replay audit benchmark").

## Reporting security issues

Please do not open a public issue for a vulnerability. Use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"). [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md) describes the scope and known limits.

## License

By contributing you agree that your contributions are licensed under the MIT License.
