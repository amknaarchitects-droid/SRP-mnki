"""
SRP Command-Line Interface & End-to-End Multi-Suite Benchmark Demo
==================================================================
Usage:
  python -m srp.cli demo
  python -m srp.cli benchmark --branches 64
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Dict

from srp.bridges.gym_bridge import RolloutPool
from srp.coordinator.server import SRPCoordinator
from srp.node.daemon import SRPProviderNode
from srp.protocol.messages import ActionPayload, SnapshotManifest
from srp.settlement.base import (
    FiatAndApiCreditLedger,
    OpenScienceKarmaLedger,
    TokenEscrowLedger,
)


def _make_distinct_pages(prefix: str, num_pages: int = 8) -> str:
    return "".join(
        f"{prefix}_BLOCK_{i:04d}_" + ("#" * (4096 - len(f"{prefix}_BLOCK_{i:04d}_")))
        for i in range(num_pages)
    )


def build_default_manifests() -> Dict[str, SnapshotManifest]:
    """Create sample base snapshots for all 4 flagship RL verifier suites."""
    # 1. Code & SWE-Bench Suite
    code_manifest = SnapshotManifest(
        snapshot_id="snap_swe_sorting_v1",
        suite="srp-env-code",
        runtime="wasm_cow",
        initial_files={
            "README.md": _make_distinct_pages("SWE_REPO_INDEX", 12),
            "solution.py": "def merge_intervals(intervals):\n    return intervals\n",
            "test_suite.py": (
                "def test_basic():\n"
                "    assert merge_intervals([[1,3],[2,6],[8,10],[15,18]]) == [[1,6],[8,10],[15,18]]\n"
                "def test_touching():\n"
                "    assert merge_intervals([[1,4],[4,5]]) == [[1,5]]\n"
            ),
        },
    )

    # 2. Formal Math / Lean 4 Suite
    math_manifest = SnapshotManifest(
        snapshot_id="snap_lean4_algebra_v1",
        suite="srp-env-math",
        runtime="wasm_cow",
        initial_files={
            "MathlibCache.bin": _make_distinct_pages("MATHLIB_OLEAN", 16),
            "theorem_state.json": json.dumps(
                {
                    "theorem": "theorem add_comm_assoc (a b c : Nat) : a + b + c = c + b + a",
                    "goals": ["a + b + c = c + b + a"],
                    "tactic_transitions": {
                        "a + b + c = c + b + a::rw [Nat.add_assoc]": ["a + (b + c) = c + b + a"],
                        "a + (b + c) = c + b + a::omega": [],
                    },
                    "proof_trace": [],
                }
            ),
        },
    )

    # 3. Headless DOM / Web Agent Suite
    web_manifest = SnapshotManifest(
        snapshot_id="snap_web_checkout_v1",
        suite="srp-env-web",
        runtime="wasm_cow",
        initial_files={
            "vendor_bundle.js": "// Pre-cached vendor DOM assets\n" + ("W" * 12288),
            "dom_state.json": json.dumps(
                {
                    "url": "https://shop.example/checkout",
                    "elements": {
                        "#coupon-input": {"tag": "input", "label": "Coupon", "value": ""},
                        "#apply-btn": {"tag": "button", "label": "Apply", "clicked": False},
                        "#pay-btn": {
                            "tag": "button",
                            "label": "Complete Order",
                            "clicked": False,
                            "navigate_to": "https://shop.example/Receipt",
                        },
                    },
                    "goal_conditions": {
                        "required_values": {"#coupon-input": "HUMANITY2026"},
                        "required_clicks": ["#apply-btn", "#pay-btn"],
                        "required_url": "https://shop.example/Receipt",
                    },
                }
            ),
        },
    )

    # 4. 3D CAD Geometry & Physics Suite
    cad_manifest = SnapshotManifest(
        snapshot_id="snap_cad_pedestal_v1",
        suite="srp-env-spatial",
        runtime="container_tmpfs",
        initial_files={
            "kernel_tables.dat": "BREP_TESSELLATION_LUT_" + ("C" * 12288),
            "cad_scene.json": json.dumps(
                {
                    "primitives": [
                        {"type": "box", "center": [0.0, 0.0, 1.0], "size": [10.0, 10.0, 2.0]}
                    ],
                    "design_spec": {
                        "target_volume": 1000.0,
                        "volume_tolerance": 25.0,
                        "max_bbox": [12.0, 12.0, 20.0],
                        "max_com_xy_offset": 0.5,
                    },
                }
            ),
        },
    )

    return {
        "code": code_manifest,
        "math": math_manifest,
        "web": web_manifest,
        "cad": cad_manifest,
    }


def run_demo() -> None:
    print("=" * 78)
    print("  SHARE RAM PROTOCOL (SRP v0.3.0) — PUBLIC GOOD RL VERIFIER FABRIC DEMO")
    print("=" * 78)

    # Initialize Coordinator with TokenEscrowLedger (or Fiat/Karma)
    ledger = TokenEscrowLedger(token_symbol="SRP_USDC", rate_per_gb_hour=0.05, rate_per_step=0.002)
    coordinator = SRPCoordinator(settlement_provider=ledger)

    # Register 2 Contributor RAM Nodes
    node_a = SRPProviderNode(node_id="node_cairo_16gb", ram_capacity_mb=512)
    node_b = SRPProviderNode(node_id="node_zurich_32gb", ram_capacity_mb=512)
    coordinator.register_node(node_a)
    coordinator.register_node(node_b)

    manifests = build_default_manifests()
    for m in manifests.values():
        coordinator.broadcast_snapshot(m)

    # 1. Verify RAM Residency (Anti-SSD-Swap Challenge)
    ok_a, ping_ms = coordinator.verify_node_ram_residency(
        "node_cairo_16gb", "snap_swe_sorting_v1"
    )
    print(
        f"\n[1] Proof-of-Honest-RAM Ping (node_cairo_16gb): "
        f"{'PASSED' if ok_a else 'FAILED'} in {ping_ms:.3f} ms"
    )

    # 2. Suite 1: Code & SWE-Bench GRPO Group Rollout (16 parallel CoW branches)
    print("\n[2] Suite 1 (`srp-env-code`): Running 16-Branch GRPO Rollout in CoW RAM...")
    correct_code = (
        "def merge_intervals(intervals):\n"
        "    if not intervals:\n"
        "        return []\n"
        "    intervals = sorted(intervals, key=lambda x: x[0])\n"
        "    merged = [list(intervals[0])]\n"
        "    for s, e in intervals[1:]:\n"
        "        if s <= merged[-1][1]:\n"
        "            merged[-1][1] = max(merged[-1][1], e)\n"
        "        else:\n"
        "            merged.append([s, e])\n"
        "    return merged\n"
    )
    buggy_code = "def merge_intervals(intervals):\n    return sorted(intervals)\n"

    code_pool = RolloutPool(coordinator, "snap_swe_sorting_v1")
    actions = [
        ActionPayload("apply_patch", {"code": correct_code if i % 4 == 0 else buggy_code})
        for i in range(16)
    ]
    grpo_out = code_pool.run_grpo_group(actions, evict_after=False)
    print(
        f"    -> Forked 16 CoW branches in {grpo_out['fork_latency_ms']:.3f} ms | "
        f"Mean Reward: {grpo_out['mean_reward']} | Sample Advantages: {grpo_out['advantages'][:4]}"
    )

    # 3. Suite 2: Formal Math / Lean 4 Multi-Turn Tactic Rollout
    print("\n[3] Suite 2 (`srp-env-math`): Multi-Turn Formal Proof Verification...")
    math_branches, _ = coordinator.fork("snap_lean4_algebra_v1", count=1)
    mb_id = math_branches[0]
    r1 = coordinator.step(mb_id, ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"}))
    r2 = coordinator.step(mb_id, ActionPayload("apply_tactic", {"tactic": "omega"}))
    print(f"    -> Step 1 Reward: {r1.reward} | Step 2 Reward: {r2.reward} ({r2.observation.stdout})")

    # 4. Suite 3: Headless DOM / Web Agent Rollout
    print("\n[4] Suite 3 (`srp-env-web`): Headless DOM Multi-Step Checkout Agent...")
    web_branches, _ = coordinator.fork("snap_web_checkout_v1", count=1)
    wb_id = web_branches[0]
    coordinator.step(
        wb_id,
        ActionPayload("fill_input", {"selector": "#coupon-input", "value": "HUMANITY2026"}),
    )
    coordinator.step(wb_id, ActionPayload("click", {"selector": "#apply-btn"}))
    w_final = coordinator.step(wb_id, ActionPayload("click", {"selector": "#pay-btn"}))
    print(f"    -> Final Web Agent Reward: {w_final.reward} | Terminated: {w_final.terminated}")

    # 5. Suite 4: 3D CAD Geometry & Static Stability Verifier
    print("\n[5] Suite 4 (`srp-env-spatial`): 3D CAD Assembly & Center-of-Mass Stability...")
    cad_branches, _ = coordinator.fork("snap_cad_pedestal_v1", count=1)
    cb_id = cad_branches[0]
    c_res = coordinator.step(
        cb_id,
        ActionPayload(
            "add_primitive",
            {
                "primitive": {
                    "type": "box",
                    "center": [0.0, 0.0, 7.0],
                    "size": [8.0, 10.0, 10.0],
                }
            },
        ),
    )
    print(f"    -> CAD Verifier Reward: {c_res.reward} | {c_res.observation.stdout.splitlines()[0]}")

    # 6. Telemetry & CoW RAM Savings Report
    telemetry = coordinator.cluster_telemetry()
    active_branches = sum(
        int(n["active_branches"]) for n in telemetry["nodes"].values()
    )
    print("\n[6] Cluster Copy-on-Write (CoW) RAM Efficiency & Settlement Report:")
    print(f"    -> Active CoW Branches Held in RAM : {active_branches}")
    print(f"    -> Unshared Logical Memory         : {telemetry['cluster_logical_bytes'] / 1024:.1f} KB")
    print(f"    -> Actual Physical RAM Used        : {telemetry['cluster_used_ram_bytes'] / 1024:.1f} KB")
    print(f"    -> CoW RAM Bandwidth/Memory Saved  : {telemetry['cluster_cow_savings_percent']}%")
    print(f"    -> Settlement Merkle Claim Root    : {ledger.compute_payout_merkle_root()[:24]}...")
    print(f"    -> Contributor Balances            : {json.dumps(telemetry['settlement']['accounts'], indent=6)}")
    print("=" * 78)


def run_benchmark(branches: int = 64) -> None:
    print("=" * 78)
    print(f"  SRP v0.3.0 — COPY-ON-WRITE FORK & VERIFIER BENCHMARK ({branches} BRANCHES)")
    print("=" * 78)
    coordinator = SRPCoordinator()
    node = SRPProviderNode(node_id="bench_node", ram_capacity_mb=1024)
    coordinator.register_node(node)

    manifests = build_default_manifests()
    coordinator.broadcast_snapshot(manifests["math"])

    branch_ids, fork_ms = coordinator.fork("snap_lean4_algebra_v1", count=branches)
    for i, bid in enumerate(branch_ids):
        tactic = "rw [Nat.add_assoc]" if i % 2 == 0 else "omega"
        coordinator.step(bid, ActionPayload("apply_tactic", {"tactic": tactic}))

    telemetry = coordinator.cluster_telemetry()
    print(f"  Forked {branches} CoW branches in : {fork_ms:.3f} ms ({fork_ms / max(1, branches):.4f} ms/branch)")
    print(f"  Unshared Logical Memory        : {telemetry['cluster_logical_bytes'] / 1024:.1f} KB")
    print(f"  Actual Physical RAM Used       : {telemetry['cluster_used_ram_bytes'] / 1024:.1f} KB")
    print(f"  CoW RAM Savings                : {telemetry['cluster_cow_savings_percent']}%")
    print("=" * 78)


def main() -> None:
    parser = argparse.ArgumentParser(description="Share RAM Protocol (SRP) CLI")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo", help="Run the full 4-suite CoW RL verification & settlement demo")
    bench_parser = sub.add_parser(
        "benchmark", help="Run a multi-branch CoW fork and verifier throughput benchmark"
    )
    bench_parser.add_argument(
        "--branches", type=int, default=64, help="Number of parallel CoW branches to fork"
    )
    args = parser.parse_args()

    if args.cmd in (None, "demo"):
        run_demo()
    elif args.cmd == "benchmark":
        run_benchmark(branches=args.branches)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
