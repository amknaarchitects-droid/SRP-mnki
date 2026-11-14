"""
Benchmark 4: compute spent on blind replay audits, relative to useful work.

For each audit configuration the same episodes are run and two things are measured:

  duplicated work   auditor steps executed / provider steps executed
  wall-clock cost   total time relative to the unaudited baseline

The coordinator always audits rewarded, terminal and timed-out steps unless
`audit_rewarded_steps=False`, so the effective audit fraction depends on the
workload, not only on `audit_rate`. Canaries are off to isolate replay audits.
The auditor here runs in the coordinator's own process, on the same hardware.
"""

from __future__ import annotations

import argparse
import time
from typing import Any, Dict, List, Tuple

from benchmarks import common
from srp.coordinator.server import SRPCoordinator
from srp.node.daemon import SRPProviderNode

NAME = "replay_audit_overhead"

# (label, audit_rate, audit_rewarded_steps)
CONFIGS: List[Tuple[str, float, bool]] = [
    ("baseline: no audits", 0.0, False),
    ("rate 0.05, sampling only", 0.05, False),
    ("rate 0.25, sampling only", 0.25, False),
    ("rate 0, plus every rewarded step", 0.0, True),
    ("rate 0.05, plus every rewarded step (default)", 0.05, True),
    ("rate 1.0 (audit everything)", 1.0, True),
]


def run(quick: bool = False) -> Dict[str, Any]:
    episodes = {"web": 30, "math": 30, "code": 4} if quick else {"web": 300, "math": 300, "code": 30}
    manifests = common.manifests()
    workloads: Dict[str, Any] = {}

    for key in ("web", "math", "code"):
        manifest, actions = manifests[key], common.EPISODES[key]
        rows: List[Dict[str, Any]] = []
        for label, rate, rewarded in CONFIGS:
            coord = SRPCoordinator(canary_rate=0.0, audit_rate=rate, audit_rewarded_steps=rewarded)
            node = SRPProviderNode(node_id=f"audit_{key}", ram_capacity_mb=512)
            coord.register_node(node)
            coord.broadcast_snapshot(manifest)
            steps_before = node.steps_executed
            t0 = time.perf_counter()
            for _ in range(episodes[key]):
                bid = coord.fork(manifest.snapshot_id)[0][0]
                for action in actions:
                    coord.step(bid, action)
                coord.evict_branch(bid)
            wall_s = time.perf_counter() - t0
            useful = node.steps_executed - steps_before
            audited = common.auditor_steps(coord)
            rows.append({
                "config": label,
                "audit_rate": rate,
                "audit_rewarded_steps": rewarded,
                "provider_steps": useful,
                "auditor_steps": audited,
                "duplicated_work_ratio": round(audited / useful, 4) if useful else None,
                "audits_performed": coord.audits_performed,
                "audits_inconclusive": coord.audits_inconclusive,
                "fraud_proofs": len(coord.fraud_proofs),
                "wall_s": round(wall_s, 4),
                "ms_per_provider_step": round(wall_s * 1000.0 / useful, 4) if useful else None,
            })
        base = rows[0]["wall_s"]
        for r in rows:
            r["wall_overhead_percent"] = round((r["wall_s"] / base - 1) * 100, 1) if base else None
        workloads[key] = {"suite": manifest.suite, "steps_per_episode": len(actions),
                          "episodes": episodes[key], "rows": rows}
    return {"benchmark": NAME, "quick": quick, "workloads": workloads}


def render(result: Dict[str, Any]) -> str:
    rows = [
        "| Suite | Audit configuration | Provider steps | Auditor steps | Duplicated work | Wall-clock overhead |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for w in result["workloads"].values():
        for r in w["rows"]:
            rows.append(
                f"| `{w['suite']}` | {r['config']} | {r['provider_steps']} | {r['auditor_steps']} | "
                f"{r['duplicated_work_ratio'] * 100:.0f}% | {r['wall_overhead_percent']:+.0f}% |"
            )
    return "\n".join(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    result = run(args.quick)
    result["environment"] = common.environment()
    print(render(result))
    if args.out:
        print("wrote", common.write_json(args.out, NAME, result))


if __name__ == "__main__":
    main()
