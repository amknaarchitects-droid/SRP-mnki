"""
SRP benchmarks: reproducible measurements behind docs/ECONOMICS.md.

Run everything:      python -m benchmarks
Short smoke version: python -m benchmarks --quick --out /tmp/srp-bench
Run one benchmark:   python -m benchmarks.env_step_latency

Standard library only. `psutil` is used for memory readings when installed.
"""
