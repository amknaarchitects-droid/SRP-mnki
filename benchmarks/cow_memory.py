"""
Benchmark 3: memory actually used by Copy-on-Write forking, measured by the OS.

For 1, 4, 16 and 64 branches, a fresh process pins one snapshot, forks N branches
and writes a distinct 16 KB file into each. Three numbers are compared:

  naive           N full private copies of the snapshot (what N independent
                  containers would hold): N x snapshot bytes.
  arena accounting  what the arena says it uses (pages x 4 KB + its metadata estimate).
  OS-level        growth of the process's resident set size (RSS).

The OS-level number is the honest one: it includes Python object overhead and the
per-branch page tables that the arena's page count leaves out.
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List

from benchmarks import common

NAME = "cow_memory"
DELTA_PAGES = 4  # 16 KB written per branch


def _child(branches: int, snapshot_mb: int) -> Dict[str, Any]:
    from srp.node.daemon import SRPProviderNode
    from srp.protocol.messages import SnapshotManifest

    gc.collect()
    rss_start = common.rss_bytes()
    pages = snapshot_mb * 256
    manifest = SnapshotManifest(
        snapshot_id="bench_cow_base",
        suite="srp-env-code",
        runtime="wasm_cow",
        initial_files={"base.bin": common.distinct_text_pages(pages)},
    )
    snapshot_bytes = pages * 4096
    node = SRPProviderNode(node_id="bench_cow", ram_capacity_mb=snapshot_mb * 4 + 512)
    node.pin_snapshot(manifest)
    del manifest
    gc.collect()
    rss_pinned = common.rss_bytes()

    t0 = time.perf_counter()
    forked, _ = node.fork("bench_cow_base", count=branches)
    fork_ms = (time.perf_counter() - t0) * 1000.0
    for i, branch in enumerate(forked):
        branch.write_file("delta.txt", common.distinct_text_pages(DELTA_PAGES, f"delta{i}"))
    gc.collect()
    rss_forked = common.rss_bytes()
    stats = node.arena.stats()

    naive = branches * snapshot_bytes
    out: Dict[str, Any] = {
        "branches": branches,
        "snapshot_bytes": snapshot_bytes,
        "delta_bytes_per_branch": DELTA_PAGES * 4096,
        "fork_ms": round(fork_ms, 3),
        "naive_bytes": naive,
        "arena_used_bytes": int(stats["used_ram_bytes"]),
        "arena_reported_savings_percent": stats["cow_ram_savings_percent"],
        "arena_savings_vs_naive_percent": round((1 - stats["used_ram_bytes"] / naive) * 100, 2),
    }
    if None not in (rss_start, rss_pinned, rss_forked):
        total = rss_forked - rss_start
        out.update({
            "rss_snapshot_bytes": rss_pinned - rss_start,
            "rss_branches_bytes": rss_forked - rss_pinned,
            "rss_per_branch_bytes": round((rss_forked - rss_pinned) / branches),
            "rss_total_bytes": total,
            "os_savings_vs_naive_percent": round((1 - total / naive) * 100, 2),
            "rss_overhead_factor_on_snapshot": round((rss_pinned - rss_start) / snapshot_bytes, 3),
        })
    return out


def run(quick: bool = False) -> Dict[str, Any]:
    snapshot_mb = 8 if quick else 64
    counts = [1, 16] if quick else [1, 4, 16, 64]
    rows: List[Dict[str, Any]] = []
    env = dict(os.environ, PYTHONPATH=common.REPO_ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
    for n in counts:
        proc = subprocess.run(
            [sys.executable, "-m", "benchmarks.cow_memory", "--child", str(n), "--snapshot-mb", str(snapshot_mb)],
            capture_output=True, text=True, cwd=common.REPO_ROOT, env=env, check=True,
        )
        rows.append(json.loads(proc.stdout.strip().splitlines()[-1]))
    return {"benchmark": NAME, "quick": quick, "snapshot_mb": snapshot_mb, "rows": rows}


def _mb(value: Any) -> str:
    return "n/a" if value is None else f"{value / 2**20:.1f}"


def render(result: Dict[str, Any]) -> str:
    rows = [
        f"Snapshot: {result['snapshot_mb']} MB of distinct 4 KB pages; each branch writes 16 KB.",
        "",
        "| Branches | Naive MB | Arena accounting MB | OS-level RSS MB | RSS per extra branch KB "
        "| Saved (arena) | Saved (OS-level) |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in result["rows"]:
        per = r.get("rss_per_branch_bytes")
        os_saved = r.get("os_savings_vs_naive_percent")
        rows.append(
            f"| {r['branches']} | {_mb(r['naive_bytes'])} | {_mb(r['arena_used_bytes'])} | "
            f"{_mb(r.get('rss_total_bytes'))} | {'n/a' if per is None else f'{per / 1024:.0f}'} | "
            f"{r['arena_savings_vs_naive_percent']:.1f}% | "
            f"{'n/a' if os_saved is None else f'{os_saved:.1f}%'} |"
        )
    return "\n".join(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--out", default=None)
    parser.add_argument("--child", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--snapshot-mb", type=int, default=64, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child is not None:
        print(json.dumps(_child(args.child, args.snapshot_mb)))
        return
    result = run(args.quick)
    result["environment"] = common.environment()
    print(render(result))
    if args.out:
        print("wrote", common.write_json(args.out, NAME, result))


if __name__ == "__main__":
    main()
