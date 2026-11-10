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

    # 512 *distinct* 4KB pages (identical pages would be content-deduplicated)
    distinct = "".join(f"{i:08d}" + "X" * (PAGE_SIZE - 8) for i in range(512))
    with pytest.raises(MemoryError):
        branches[0].write_file("huge.bin", distinct)
    # Refused write leaves the branch untouched
    assert branches[0].list_files() == ["a.txt"]
    assert arena.dirty_ram_bytes == 0


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
            # Stacked on the 10x10x2 base (z 0..2) without overlap: 200 + 800 = 1000
            {"primitive": {"type": "box", "center": [0.0, 0.0, 7.0], "size": [8.0, 10.0, 10.0]}},
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


def test_intermediate_branch_fork_no_double_counting_or_leak():
    """Verify MCTS sub-branching does not double-count RAM or leak pages after eviction."""
    arena = VolatileRAMArena(capacity_mb=16)
    manifest = SnapshotManifest(
        snapshot_id="snap_mcts_leak_check",
        suite="srp-env-code",
        initial_files={"state.txt": "root_state"},
    )
    snap = arena.pin_snapshot(manifest)
    assert snap.state_hash == manifest.content_merkle_root
    initial_base = arena.base_ram_bytes
    assert initial_base == PAGE_SIZE
    assert arena.dirty_ram_bytes == 0

    b1_list, _ = arena.fork("snap_mcts_leak_check", count=1)
    b1 = b1_list[0]
    b1.write_file("state.txt", "mutated_at_depth_1")
    assert arena.base_ram_bytes == initial_base
    assert arena.dirty_ram_bytes == PAGE_SIZE
    assert arena.used_ram_bytes == initial_base + PAGE_SIZE

    # Fork 4 child branches from b1: must share b1's dirty page without double counting
    children, _ = arena.fork(b1.branch_id, count=4)
    assert arena.base_ram_bytes == initial_base
    assert arena.dirty_ram_bytes == PAGE_SIZE
    assert arena.used_ram_bytes == initial_base + PAGE_SIZE

    # Evict parent b1 first: children must still read b1's dirty page cleanly
    arena.evict_branch(b1.branch_id)
    assert arena.dirty_ram_bytes == PAGE_SIZE
    assert all(c.read_file("state.txt") == "mutated_at_depth_1" for c in children)

    # Evict all children: dirty RAM must return to 0 with base RAM untouched
    for c in children:
        arena.evict_branch(c.branch_id)
    assert arena.dirty_ram_bytes == 0
    assert arena.base_ram_bytes == initial_base


def test_file_overwrite_and_delete_reclaims_dirty_pages():
    """Verify overwriting or deleting files in a branch reclaims superseded dirty pages."""
    arena = VolatileRAMArena(capacity_mb=16)
    manifest = SnapshotManifest(
        snapshot_id="snap_overwrite",
        suite="srp-env-code",
        initial_files={"base.txt": "immutable"},
    )
    arena.pin_snapshot(manifest)
    branches, _ = arena.fork("snap_overwrite", count=1)
    branch = branches[0]

    for step_idx in range(10):
        branch.write_file("scratch.log", f"iteration_{step_idx}")
        # Overwriting a 1-page file must keep exactly 1 dirty page, not 10
        assert branch.dirty_page_count == 1
        assert arena.dirty_ram_bytes == PAGE_SIZE

    branch.delete_file("scratch.log")
    assert branch.dirty_page_count == 0
    assert arena.dirty_ram_bytes == 0


def test_snapshot_eviction_reclaims_base_pages():
    """Verify evicting a snapshot drops dependent branches and frees base pages."""
    coordinator = SRPCoordinator()
    node = SRPProviderNode(node_id="node_evict", ram_capacity_mb=64)
    coordinator.register_node(node)

    manifest = SnapshotManifest(
        snapshot_id="snap_temp",
        suite="srp-env-code",
        initial_files={"a.py": "x = 1\n", "b.py": "y = 2\n"},
    )
    coordinator.broadcast_snapshot(manifest)
    assert node.arena.base_ram_bytes == 2 * PAGE_SIZE
    coordinator.fork("snap_temp", count=3)
    ballast_bytes = node.arena.ballast_ram_bytes
    assert ballast_bytes == coordinator.min_ballast_pages * PAGE_SIZE

    reclaimed = coordinator.evict_snapshot("snap_temp", evict_branches=True)
    # Base pages plus the node-unique residency ballast are all reclaimed
    assert reclaimed == 2 * PAGE_SIZE + ballast_bytes
    assert node.arena.used_ram_bytes == 0
    assert node.arena.stats()["active_branches"] == 0


def test_tamper_proof_memory_ping_and_MultiTurn_billing():
    """Verify MemoryPing detects corrupted node pages and read-only steps do not re-bill dirty pages."""
    ledger = FiatAndApiCreditLedger(rate_per_gb_hour=1.0, rate_per_step=0.1)
    coordinator = SRPCoordinator(settlement_provider=ledger)
    node = SRPProviderNode(node_id="node_tamper", ram_capacity_mb=64)
    coordinator.register_node(node)

    manifests = build_default_manifests()
    coordinator.broadcast_snapshot(manifests["math"])

    # Step 1 mutates proof state (2 dirty pages: theorem_state.json + ProofHistory.lean)
    b_ids, _ = coordinator.fork("snap_lean4_algebra_v1", count=1)
    res1 = coordinator.step(
        b_ids[0], ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"})
    )
    assert res1.metrics.step_dirty_pages == 2
    pages_after_step1 = ledger.get_account("node_tamper").total_dirty_pages_served
    assert pages_after_step1 == 2

    # Step 2 is read-only (`inspect_goals`): must bill 0 newly dirtied pages
    res2 = coordinator.step(b_ids[0], ActionPayload("inspect_goals", {}))
    assert res2.metrics.step_dirty_pages == 0
    assert ledger.get_account("node_tamper").total_dirty_pages_served == pages_after_step1

    # Corrupt all base pages in node's arena and verify Coordinator catches it via canonical manifest
    for phash in list(node.arena._base_pages.keys()):
        node.arena._base_pages[phash] = b"\xff" * PAGE_SIZE
    ok, _ = coordinator.verify_node_ram_residency("node_tamper", "snap_lean4_algebra_v1")
    assert ok is False


def test_verifier_anti_reward_hacking_and_input_validation():
    """Verify code, math, web, and CAD verifiers block reward hacking and invalid inputs."""
    manifests = build_default_manifests()
    coordinator = SRPCoordinator()
    node = SRPProviderNode(node_id="node_sec", ram_capacity_mb=128)
    coordinator.register_node(node)
    for m in manifests.values():
        coordinator.broadcast_snapshot(m)

    # 1. Code verifier: block overwriting test_suite.py and block fake test_* injection
    cb, _ = coordinator.fork("snap_swe_sorting_v1", count=1)
    hack_overwrite = coordinator.step(
        cb[0],
        ActionPayload("apply_patch", {"path": "test_suite.py", "code": "def test_win(): pass"}),
    )
    assert hack_overwrite.reward == 0.0
    assert hack_overwrite.observation.exit_code == 1

    hack_inject = coordinator.step(
        cb[0],
        ActionPayload(
            "apply_patch",
            {
                "code": (
                    "def merge_intervals(x): return []\n"
                    "def test_fake1(): assert True\n"
                    "def test_fake2(): assert True\n"
                    "def test_fake3(): assert True\n"
                )
            },
        ),
    )
    assert hack_inject.reward == 0.0
    assert hack_inject.observation.structured_data["total"] == 2

    # 2. Math verifier: `rfl` cannot prove `a + b + c = c + b + a`, but `omega` handles grouped parens
    mb, _ = coordinator.fork("snap_lean4_algebra_v1", count=1)
    bad_rfl = coordinator.step(mb[0], ActionPayload("apply_tactic", {"tactic": "rfl"}))
    assert bad_rfl.reward == 0.0

    # 3. Web verifier: repeating the same click does not farm shaping rewards
    wb, _ = coordinator.fork("snap_web_checkout_v1", count=1)
    r_click1 = coordinator.step(wb[0], ActionPayload("click", {"selector": "#apply-btn"}))
    assert r_click1.reward > 0.0
    r_click2 = coordinator.step(wb[0], ActionPayload("click", {"selector": "#apply-btn"}))
    assert r_click2.reward == 0.0

    # 4. Spatial CAD verifier: reject negative dimensions and malformed centers cleanly
    sb, _ = coordinator.fork("snap_cad_pedestal_v1", count=1)
    bad_cad = coordinator.step(
        sb[0],
        ActionPayload(
            "add_primitive",
            {"primitive": {"type": "box", "center": [0.0, 0.0, 1.0], "size": [-5.0, 2.0, 2.0]}},
        ),
    )
    assert bad_cad.reward == 0.0
    assert bad_cad.observation.exit_code == 1


def test_concurrent_multithreaded_rollouts_and_stdout_isolation():
    """Verify thread safety and stdout isolation across 16 concurrent worker threads."""
    from concurrent.futures import ThreadPoolExecutor

    manifests = build_default_manifests()
    coordinator = SRPCoordinator()
    node = SRPProviderNode(node_id="node_concurrent", ram_capacity_mb=256)
    coordinator.register_node(node)
    coordinator.broadcast_snapshot(manifests["code"])

    def worker(worker_id: int) -> None:
        b_ids, _ = coordinator.fork("snap_swe_sorting_v1", count=1)
        bid = b_ids[0]
        try:
            marker = f"WORKER_MARKER_{worker_id:04d}_END"
            code = (
                "def merge_intervals(intervals):\n"
                f"    print('{marker}')\n"
                "    intervals = sorted(intervals, key=lambda x: x[0])\n"
                "    out = [list(intervals[0])]\n"
                "    for s, e in intervals[1:]:\n"
                "        if s <= out[-1][1]: out[-1][1] = max(out[-1][1], e)\n"
                "        else: out.append([s, e])\n"
                "    return out\n"
            )
            res = coordinator.step(bid, ActionPayload("apply_patch", {"code": code}))
            assert res.reward == 1.0
            assert marker in res.observation.stdout
            # Ensure no other worker's marker leaked into this branch's stdout
            for other_id in range(16):
                if other_id != worker_id:
                    assert f"WORKER_MARKER_{other_id:04d}_END" not in res.observation.stdout
            coordinator.cluster_telemetry()
        finally:
            coordinator.evict_branch(bid)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(worker, i) for i in range(16)]
        for f in futures:
            f.result()

    assert len(coordinator.fraud_proofs) == 0
    assert node.arena.dirty_ram_bytes == 0


def test_concurrent_steps_on_same_branch_do_not_slash_honest_node():
    """Regression (R1): parallel steps on one branch must not break the hash chain."""
    import threading

    ledger = FiatAndApiCreditLedger()
    coordinator = SRPCoordinator(settlement_provider=ledger)
    node = SRPProviderNode(node_id="node_race", ram_capacity_mb=64)
    coordinator.register_node(node)
    coordinator.broadcast_snapshot(build_default_manifests()["web"])
    bid = coordinator.fork("snap_web_checkout_v1", count=1)[0][0]

    errors = []

    def hammer(tag: str) -> None:
        for i in range(25):
            try:
                coordinator.step(
                    bid,
                    ActionPayload(
                        "fill_input", {"selector": "#coupon-input", "value": f"{tag}_{i}"}
                    ),
                )
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

    threads = [threading.Thread(target=hammer, args=(f"t{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert coordinator.fraud_proofs == []
    acct = ledger.get_account("node_race")
    assert acct.canary_failures == 0
    assert acct.verified_steps == 100
    assert coordinator._branch_state_hashes[bid] == node.arena.get_branch(bid).state_hash


def test_code_verifier_rejects_agent_selected_test_file():
    """Regression (S2): the agent cannot grade itself against a test file it wrote."""
    coordinator = SRPCoordinator()
    node = SRPProviderNode(node_id="node_testpath", ram_capacity_mb=64)
    coordinator.register_node(node)
    coordinator.broadcast_snapshot(build_default_manifests()["code"])
    bid = coordinator.fork("snap_swe_sorting_v1", count=1)[0][0]

    coordinator.step(
        bid,
        ActionPayload("apply_patch", {"path": "my_tests.py", "code": "def test_ok():\n    pass\n"}),
    )
    hack = coordinator.step(
        bid,
        ActionPayload(
            "apply_patch", {"path": "solution.py", "code": "x = 1", "test_path": "my_tests.py"}
        ),
    )
    assert hack.reward == 0.0
    assert hack.terminated is False
    assert "test_path is fixed" in hack.observation.stderr

    # Explicitly naming the pinned test file is still allowed
    ok = coordinator.step(
        bid,
        ActionPayload(
            "apply_patch",
            {"code": "def merge_intervals(x):\n    return x\n", "test_path": "test_suite.py"},
        ),
    )
    assert ok.observation.structured_data["total"] == 2


def test_refused_snapshot_eviction_keeps_snapshot_routable():
    """Regression (R2): a refused eviction must not orphan the snapshot in the coordinator."""
    coordinator = SRPCoordinator()
    node = SRPProviderNode(node_id="node_refuse", ram_capacity_mb=64)
    coordinator.register_node(node)
    coordinator.broadcast_snapshot(build_default_manifests()["code"])
    coordinator.fork("snap_swe_sorting_v1", count=1)

    with pytest.raises(RuntimeError):
        coordinator.evict_snapshot("snap_swe_sorting_v1", evict_branches=False)

    # Still pinned on the node and still routable / pingable through the coordinator
    assert "snap_swe_sorting_v1" in node.arena._snapshots
    new_ids, _ = coordinator.fork("snap_swe_sorting_v1", count=1)
    assert len(new_ids) == 1
    ok, _ = coordinator.verify_node_ram_residency("node_refuse", "snap_swe_sorting_v1")
    assert ok is True

    # A subsequent full eviction succeeds and clears coordinator state
    coordinator.evict_snapshot("snap_swe_sorting_v1", evict_branches=True)
    assert node.arena.used_ram_bytes == 0
    assert coordinator._branch_to_node == {}
    with pytest.raises(KeyError):
        coordinator.fork("snap_swe_sorting_v1", count=1)


def test_cross_snapshot_identical_page_survives_other_snapshot_eviction():
    """Regression (R3): a branch page equal to another snapshot's base page must stay readable."""
    arena = VolatileRAMArena(capacity_mb=8)
    arena.pin_snapshot(
        SnapshotManifest("snap_A", "srp-env-code", "wasm_cow", {"f.txt": "SHARED_CONTENT"})
    )
    arena.pin_snapshot(
        SnapshotManifest("snap_B", "srp-env-code", "wasm_cow", {"g.txt": "other"})
    )
    branch = arena.fork("snap_B", count=1)[0][0]
    branch.write_file("h.txt", "SHARED_CONTENT")
    assert branch.dirty_page_count == 1

    arena.evict_snapshot("snap_A")
    assert branch.read_file("h.txt") == "SHARED_CONTENT"

    arena.evict_branch(branch.branch_id)
    assert arena.dirty_ram_bytes == 0
    arena.evict_snapshot("snap_B")
    assert arena.used_ram_bytes == 0

    # Reverse order: pinning a snapshot whose page equals a live branch's dirty page
    arena.pin_snapshot(SnapshotManifest("snap_C", "srp-env-code", "wasm_cow", {"x": "c"}))
    br_c = arena.fork("snap_C", count=1)[0][0]
    br_c.write_file("y", "LATER_PINNED")
    arena.pin_snapshot(
        SnapshotManifest("snap_D", "srp-env-code", "wasm_cow", {"z": "LATER_PINNED"})
    )
    arena.evict_snapshot("snap_D")
    assert br_c.read_file("y") == "LATER_PINNED"
    arena.evict_branch(br_c.branch_id)
    assert arena.dirty_ram_bytes == 0
