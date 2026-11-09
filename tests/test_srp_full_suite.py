"""
Comprehensive Test Suite for the Share RAM Protocol (SRP)
=========================================================
Tests:
  1. 4KB Page-Granular Copy-on-Write (CoW) RAM Arena & Tree Branching (`SRP_FORK`)
  2. Memory Ceiling Enforcement (Anti-Swap Protection)
  3. All 4 Flagship Verifier Suites (`code`, `math`, `web`, `spatial`)
  4. Proof-of-Honest-RAM (`MemoryPingChallenge`) & Cryptographic Receipts
  5. Blind Canary Fraud Detection & Slashing
  6. Agnostic Economic Settlement Ledgers (Fiat/Credits, Token Merkle Root, Karma)
  7. Gymnasium & GRPO RolloutPool Bridges
"""

from __future__ import annotations

import pytest

import srp
from srp.cli import build_default_manifests
from srp.coordinator.server import SRPCoordinator
from srp.node.daemon import SRPProviderNode
from srp.node.ram_arena import PAGE_SIZE, VolatileRAMArena
from srp.protocol.messages import ActionPayload, SnapshotManifest
from srp.settlement.base import (
    FiatAndApiCreditLedger,
    OpenScienceKarmaLedger,
    TokenEscrowLedger,
)


def test_cow_ram_arena_fork_savings_and_isolation():
    """Verify that forking 32 branches shares base 4KB pages and isolates mutations."""
    arena = VolatileRAMArena(capacity_mb=64)
    # 10 distinct 4KB pages (40 KB total)
    large_file = "".join(f"PAGE_{i:04d}_" + ("A" * (PAGE_SIZE - 10)) for i in range(10))
    manifest = SnapshotManifest(
        snapshot_id="snap_test_cow",
        suite="srp-env-code",
        initial_files={"big.txt": large_file, "small.txt": "initial"},
    )

    snap = arena.pin_snapshot(manifest)
    base_bytes = arena.base_ram_bytes
    assert base_bytes == 11 * PAGE_SIZE

    # Fork 32 branches from the snapshot
    branches, fork_ms = arena.fork("snap_test_cow", count=32)
    assert len(branches) == 32
    assert fork_ms < 50.0
    # Zero dirty pages allocated immediately after fork
    assert arena.dirty_ram_bytes == 0

    # Mutate small.txt in branch 0 only
    newly_dirtied = branches[0].write_file("small.txt", "mutated_in_branch_0")
    assert newly_dirtied == 1
    assert branches[0].read_file("small.txt") == "mutated_in_branch_0"
    # Branch 1 must remain completely untouched
    assert branches[1].read_file("small.txt") == "initial"
    # Unchanged 40KB file in branch 0 still reads cleanly from shared base pages
    assert branches[0].read_file("big.txt") == large_file

    stats = arena.stats()
    assert stats["cow_ram_savings_percent"] > 95.0


def test_multi_turn_tree_branching_from_intermediate_branch():
    """Verify MCTS-style sub-branching from an already mutated CoWBranch."""
    arena = VolatileRAMArena(capacity_mb=32)
    manifest = SnapshotManifest(
        snapshot_id="snap_tree",
        suite="srp-env-code",
        initial_files={"state.txt": "step_0"},
    )
    arena.pin_snapshot(manifest)

    b1_list, _ = arena.fork("snap_tree", count=1)
    b1 = b1_list[0]
    b1.write_file("state.txt", "step_1")

    # Now fork 4 child sub-branches directly from b1
    children, _ = arena.fork(b1.branch_id, count=4)
    assert all(c.read_file("state.txt") == "step_1" for c in children)

    children[0].write_file("state.txt", "step_2_child_0")
    assert children[0].read_file("state.txt") == "step_2_child_0"
    assert children[1].read_file("state.txt") == "step_1"


def test_ram_arena_hard_ceiling_prevents_swap():
    """Verify VolatileRAMArena raises MemoryError rather than exceeding capacity."""
    arena = VolatileRAMArena(capacity_mb=1)  # 1 MB ceiling
    manifest = SnapshotManifest(
        snapshot_id="snap_small",
        suite="srp-env-code",
        initial_files={"a.txt": "hello"},
    )
    arena.pin_snapshot(manifest)
    branches, _ = arena.fork("snap_small", count=1)

    with pytest.raises(MemoryError):
        branches[0].write_file("huge.bin", "X" * (2 * 1024 * 1024))


def test_all_four_flagship_verifier_suites_end_to_end():
    """Verify Code, Math/Lean, Web/DOM, and 3D Spatial/CAD verifiers."""
    manifests = build_default_manifests()
    coordinator = SRPCoordinator()
    node = SRPProviderNode(node_id="node_test", ram_capacity_mb=128)
    coordinator.register_node(node)

    for m in manifests.values():
        coordinator.broadcast_snapshot(m)

    # 1. Code Verifier
    cb, _ = coordinator.fork("snap_swe_sorting_v1", count=1)
    good_code = (
        "def merge_intervals(intervals):\n"
        "    intervals = sorted(intervals, key=lambda x: x[0])\n"
        "    out = [list(intervals[0])]\n"
        "    for s, e in intervals[1:]:\n"
        "        if s <= out[-1][1]: out[-1][1] = max(out[-1][1], e)\n"
        "        else: out.append([s, e])\n"
        "    return out\n"
    )
    res_code = coordinator.step(cb[0], ActionPayload("apply_patch", {"code": good_code}))
    assert res_code.reward == 1.0
    assert res_code.terminated is True

    # 2. Math / Lean Verifier
    mb, _ = coordinator.fork("snap_lean4_algebra_v1", count=1)
    r_math1 = coordinator.step(mb[0], ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"}))
    assert r_math1.reward > 0.0 and not r_math1.terminated
    r_math2 = coordinator.step(mb[0], ActionPayload("apply_tactic", {"tactic": "omega"}))
    assert r_math2.reward == 1.0 and r_math2.terminated is True

    # 3. Web DOM Verifier
    wb, _ = coordinator.fork("snap_web_checkout_v1", count=1)
    coordinator.step(wb[0], ActionPayload("fill_input", {"selector": "#coupon-input", "value": "HUMANITY2026"}))
    coordinator.step(wb[0], ActionPayload("click", {"selector": "#apply-btn"}))
    r_web = coordinator.step(wb[0], ActionPayload("click", {"selector": "#pay-btn"}))
    assert r_web.reward == 1.0 and r_web.terminated is True

    # 4. Spatial 3D CAD Verifier
    sb, _ = coordinator.fork("snap_cad_pedestal_v1", count=1)
    r_cad = coordinator.step(
        sb[0],
        ActionPayload(
            "add_primitive",
            {"primitive": {"type": "box", "center": [0.0, 0.0, 6.0], "size": [8.0, 10.0, 10.0]}},
        ),
    )
    assert r_cad.reward == 1.0 and r_cad.terminated is True


def test_proof_of_honest_ram_and_canary_slashing():
    """Verify MemoryPingChallenge and Canary Fraud Proof slashing."""
    ledger = FiatAndApiCreditLedger(rate_per_gb_hour=1.0, rate_per_step=0.5)
    coordinator = SRPCoordinator(settlement_provider=ledger)
    node = SRPProviderNode(node_id="node_honest", ram_capacity_mb=64)
    coordinator.register_node(node)

    manifests = build_default_manifests()
    coordinator.broadcast_snapshot(manifests["math"])

    # Verify physical RAM residency ping
    ok, latency_ms = coordinator.verify_node_ram_residency("node_honest", "snap_lean4_algebra_v1")
    assert ok is True
    assert latency_ms < 10.0

    # Execute a valid step to earn balance
    b_ids, _ = coordinator.fork("snap_lean4_algebra_v1", count=1)
    coordinator.step(b_ids[0], ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"}))
    acct_before = ledger.get_account("node_honest").balance_units
    assert acct_before > 0.5

    # Pass an honest canary check
    passed, fp = coordinator.inject_canary_audit(
        node_id="node_honest",
        snapshot_id="snap_lean4_algebra_v1",
        canary_action=ActionPayload("apply_tactic", {"tactic": "invalid_tactic"}),
        expected_reward=0.0,
    )
    assert passed is True
    assert fp is None

    # Simulate a canary mismatch (expecting 1.0 when node returns 0.0) -> triggers FraudProof & slash
    passed_bad, fp_bad = coordinator.inject_canary_audit(
        node_id="node_honest",
        snapshot_id="snap_lean4_algebra_v1",
        canary_action=ActionPayload("apply_tactic", {"tactic": "invalid_tactic"}),
        expected_reward=1.0,
    )
    assert passed_bad is False
    assert fp_bad is not None
    assert ledger.get_account("node_honest").canary_failures == 1
    assert ledger.get_account("node_honest").slashed_units > 0


def test_pluggable_economic_ledgers_and_gym_bridge():
    """Verify TokenEscrowLedger, OpenScienceKarmaLedger, and `srp.make()`."""
    manifests = build_default_manifests()
    env = srp.make(manifests["math"])
    children = env.fork(count=4)
    obs, reward, term, trunc, info = children[0].step(
        {"command": "apply_tactic", "payload": {"tactic": "rw [Nat.add_assoc]"}}
    )
    assert reward > 0.0
    assert info["receipt"].branch_id == children[0].branch_id

    token_ledger = TokenEscrowLedger(token_symbol="SRP_TOKEN")
    token_ledger.record_verified_step("node_1", compute_ms=5.2, dirty_pages=3)
    merkle_root = token_ledger.compute_payout_merkle_root()
    assert len(merkle_root) == 64

    karma_ledger = OpenScienceKarmaLedger()
    karma_rec = karma_ledger.record_verified_step("volunteer_node", compute_ms=3.1, dirty_pages=2)
    assert karma_rec.unit_symbol == "HUMANITY_KARMA"
    assert karma_rec.new_balance >= 10.0
