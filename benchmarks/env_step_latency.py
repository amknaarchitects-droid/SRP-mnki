"""
Benchmark 1: wall-clock time per environment step, for each bundled suite.

Two paths are timed with replay audits and canaries off:
  node         SRPProviderNode.step: environment execution + signed receipt.
  coordinator  SRPCoordinator.step: the above + routing and receipt verification.

Every episode runs on a freshly forked branch, so the fork latency is reported too.
"""

from __future__ import annotations

import argparse
import time
from typing import Any, Dict, List

from benchmarks import common
from srp.node.daemon import SRPProviderNode

NAME = "env_step_latency"


def run(quick: bool = False) -> Dict[str, Any]:
    episodes = {"code": 5, "math": 40, "web": 40, "cad": 40} if quick else \
               {"code": 40, "math": 500, "web": 500, "cad": 500}
    manifests = common.manifests()
    suites: Dict[str, Any] = {}

    for key, actions in common.EPISODES.items():
        manifest = manifests[key]

        # --- node path
        node = SRPProviderNode(node_id=f"bench_{key}", ram_capacity_mb=512)
        node.pin_snapshot(manifest)
        node_ms: List[float] = []
        for _ in range(episodes[key]):
            branch = node.fork(manifest.snapshot_id)[0][0]
            for action in actions:
                t0 = time.perf_counter()
                node.step(branch.branch_id, action)
                node_ms.append((time.perf_counter() - t0) * 1000.0)
            node.evict_branch(branch.branch_id)

        # --- coordinator path
        coord = common.unaudited_coordinator()
        coord.register_node(SRPProviderNode(node_id=f"bench_c_{key}", ram_capacity_mb=512))
        coord.broadcast_snapshot(manifest)
        coord_ms: List[float] = []
        fork_ms: List[float] = []
        last_reward = None
        for _ in range(episodes[key]):
            t0 = time.perf_counter()
            bid = coord.fork(manifest.snapshot_id)[0][0]
            fork_ms.append((time.perf_counter() - t0) * 1000.0)
            for action in actions:
                t0 = time.perf_counter()
                result = coord.step(bid, action)
                coord_ms.append((time.perf_counter() - t0) * 1000.0)
                last_reward = result.reward
            coord.evict_branch(bid)

        suites[key] = {
            "suite": manifest.suite,
            "steps_per_episode": len(actions),
            "final_reward": last_reward,
            "node_step": common.summarize(node_ms),
            "coordinator_step": common.summarize(coord_ms),
            "coordinator_fork": common.summarize(fork_ms),
        }
    return {"benchmark": NAME, "quick": quick, "suites": suites}


def render(result: Dict[str, Any]) -> str:
    rows = [
        "| Suite | Path | Steps timed | p50 ms | p95 ms | p99 ms |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for key, s in result["suites"].items():
        for label, field in (("node", "node_step"), ("coordinator", "coordinator_step"),
                             ("fork (coordinator)", "coordinator_fork")):
            d = s[field]
            rows.append(
                f"| `{s['suite']}` | {label} | {d['n']} | {common.fmt_ms(d['p50_ms'])} | "
                f"{common.fmt_ms(d['p95_ms'])} | {common.fmt_ms(d['p99_ms'])} |"
            )
    return "\n".join(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--out", default=None, help="directory for the JSON result")
    args = parser.parse_args()
    result = run(args.quick)
    result["environment"] = common.environment()
    print(render(result))
    if args.out:
        print("wrote", common.write_json(args.out, NAME, result))


if __name__ == "__main__":
    main()
