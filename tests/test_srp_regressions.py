"""
Regression tests for the v0.4.0 review findings (phases 1-5).
Each test (except a few controls) failed on v0.4.0 before its fix.
"""

import json
import os
import time

import pytest

from srp.cli import build_default_manifests
from srp.coordinator.server import SRPCoordinator, verify_fraud_proof_by_replay
from srp.envs import sandbox
from srp.node.daemon import SRPProviderNode
from srp.protocol import crypto
from srp.protocol.messages import FRAUD_KIND_REPLAY, ActionPayload, FraudProof, SnapshotManifest
from srp.settlement.base import FiatAndApiCreditLedger

M = build_default_manifests()
RW = ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"})


def _cluster(stake: float = 50.0, **kw):
    kw.setdefault("canary_rate", 0.0)
    kw.setdefault("audit_rate", 0.0)
    ledger = FiatAndApiCreditLedger()
    coord = SRPCoordinator(settlement_provider=ledger, **kw)
    node = SRPProviderNode(node_id="n1", ram_capacity_mb=64)
    ledger.deposit_stake("n1", stake)
    coord.register_node(node)
    for m in M.values():
        coord.broadcast_snapshot(m)
    return coord, node, ledger


def _tamper_reward(node, step_index: int, value: float):
    honest = node.step

    def step(branch_id, action, request_id=None, timeout_ms=5000):
        res = honest(branch_id, action, request_id=request_id, timeout_ms=timeout_ms)
        if res.receipt.step_index == step_index:
            res.reward = res.receipt.reward = value
            res.receipt.sign(node._keypair)
        return res

    node.step = step


class _FixedRng:
    """Deterministic stand-in for SystemRandom: always takes a canary prefix, at full depth."""

    def shuffle(self, x):
        pass

    def choice(self, seq):
        return seq[0]

    def random(self):
        return 0.0

    def randint(self, lo, hi):
        return hi


# ----------------------------------------------------------------- H1
def test_canary_that_hits_the_wall_clock_backstop_is_inconclusive(monkeypatch):
    coord, _, ledger = _cluster()
    real, calls = sandbox.backstop_ms, {"n": 0}

    def node_under_load(timeout_ms):  # only the node's run is slow; replays are normal
        calls["n"] += 1
        return 1 if calls["n"] == 1 else real(timeout_ms)

    monkeypatch.setattr(sandbox, "backstop_ms", node_under_load)
    ok, fp = coord.inject_canary_audit(
        "n1", "snap_swe_sorting_v1",
        ActionPayload("apply_patch", {"code": "def merge_intervals(x):\n    return x\n"}),
    )
    assert ok is True and fp is None
    assert not coord.is_quarantined("n1") and ledger.stake_of("n1") == 50.0
    assert coord.canaries_inconclusive == 1


def test_registered_canary_expectations_are_only_used_at_the_root():
    coord, _, ledger = _cluster()
    coord._rng = _FixedRng()
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    coord.step(bid, RW)  # gives the canary a non-empty prefix pool
    # Correct at the root (rfl fails, state unchanged); wrong after the rw prefix.
    coord.register_canary("snap_lean4_algebra_v1", ActionPayload("apply_tactic", {"tactic": "rfl"}),
                          expected_reward=0.0, expected_state_hash=M["math"].content_merkle_root)
    assert coord.run_canary_round(["n1"]) == [("n1", True)]
    assert coord.fraud_proofs == [] and ledger.stake_of("n1") == 50.0


def test_a_lie_in_a_canary_prefix_is_slashed_as_replay_fraud_on_that_step():
    coord, node, _ = _cluster(audit_rewarded_steps=False)
    _tamper_reward(node, step_index=1, value=0.77)  # the rw prefix step really earns 0.1
    ok, fp = coord.inject_canary_audit(
        "n1", "snap_lean4_algebra_v1", ActionPayload("apply_tactic", {"tactic": "omega"}),
        prefix=[(RW, 5000)],
    )
    assert ok is False and fp.kind == FRAUD_KIND_REPLAY and fp.slashable
    assert fp.receipt.reward == 0.77 and len(fp.lineage) == 1
    assert verify_fraud_proof_by_replay(fp, M["math"])


# ----------------------------------------------------------------- H2
def _honest_receipt(manifest, action):
    node = SRPProviderNode(node_id="victim", ram_capacity_mb=64)
    node.pin_snapshot(manifest)
    bid = node.fork(manifest.snapshot_id)[0][0].branch_id
    return node, node.step(bid, action).receipt


def _proof(node, receipt, manifest, lineage):
    return FraudProof(
        node_id=node.node_id, request_id=receipt.request_id, reason="forged", expected_reward=0.0,
        actual_reward=receipt.reward, receipt=receipt, node_public_key_hex=node.public_key_hex,
        kind=FRAUD_KIND_REPLAY, root_snapshot_id=manifest.snapshot_id,
        root_content_hash=manifest.content_merkle_root, lineage=lineage,
    )


def test_a_receipt_paired_with_another_action_is_not_slashable():
    node, rec = _honest_receipt(M["math"], RW)
    fp = _proof(node, rec, M["math"], [{"command": "inspect_goals", "payload": {}, "timeout_ms": 5000}])
    assert not fp.slashable
    assert not verify_fraud_proof_by_replay(fp, M["math"])


def test_a_receipt_paired_with_another_history_fails_replay():
    web = M["web"]
    click = ActionPayload("click", {"selector": "#apply-btn"})
    node, rec = _honest_receipt(web, click)  # honestly executed at the root
    fp = _proof(node, rec, web, [
        {"command": "fill_input", "payload": {"selector": "#coupon-input", "value": "X"}, "timeout_ms": 5000},
        {"command": "click", "payload": {"selector": "#apply-btn"}, "timeout_ms": 5000},
    ])
    assert fp.slashable  # structurally bound to the last step...
    assert not verify_fraud_proof_by_replay(fp, web)  # ...but it did not start from that state


# ----------------------------------------------------------------- H3
@pytest.mark.parametrize("timeout", [120_000, 0, -5, True, 2.5])
def test_out_of_range_step_timeout_is_rejected_without_blaming_the_node(timeout):
    coord, _, _ = _cluster()
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    with pytest.raises(ValueError, match="timeout_ms"):
        coord.step(bid, ActionPayload("inspect_goals", {}), timeout_ms=timeout)
    assert not coord.is_quarantined("n1") and coord.fraud_proofs == []
    assert coord.step(bid, RW).reward == 0.1  # branch still usable


def test_coordinator_rejects_an_invalid_default_step_timeout():
    with pytest.raises(ValueError):
        SRPCoordinator(step_timeout_ms=90_000)


# ----------------------------------------------------------------- H4
def test_canary_steps_do_not_spawn_more_canaries():
    coord, _, _ = _cluster(canary_rate=1.0)
    coord.register_canary("snap_lean4_algebra_v1", ActionPayload("inspect_goals", {}))
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    coord.step(bid, ActionPayload("inspect_goals", {}))
    deadline = time.time() + 10
    while coord._canaries_in_flight and time.time() < deadline:
        time.sleep(0.05)
    assert coord._canaries_in_flight == 0
    assert coord.canaries_run == 1


def test_concurrent_canaries_are_capped():
    coord, _, _ = _cluster(canary_rate=1.0, max_concurrent_canaries=0)
    coord.register_canary("snap_lean4_algebra_v1", ActionPayload("inspect_goals", {}))
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    for _ in range(5):
        coord.step(bid, ActionPayload("inspect_goals", {}))
    time.sleep(0.2)
    assert coord.canaries_run == 0


# ----------------------------------------------------------------- H5
def test_math_tactic_cannot_borrow_another_goals_transition():
    m = SnapshotManifest("snap_math_borrow", "srp-env-math", initial_files={"theorem_state.json": json.dumps({
        "goals": ["HARD"],
        "tactic_transitions": {"HARD::step1": ["EASY"], "EASY::finish": []},
        "proof_trace": [],
    })})
    node = SRPProviderNode(node_id="n5", ram_capacity_mb=64)
    node.pin_snapshot(m)
    bid = node.fork(m.snapshot_id)[0][0].branch_id
    r = node.step(bid, ActionPayload("apply_tactic", {"tactic": "EASY::finish"}))
    assert r.reward == 0.0 and not r.terminated and r.observation.exit_code == 1
    # The intended proof still works
    assert node.step(bid, ActionPayload("apply_tactic", {"tactic": "step1"})).reward == 0.1
    assert node.step(bid, ActionPayload("apply_tactic", {"tactic": "finish"})).reward == 1.0


# ----------------------------------------------------------------- M3
def test_appeal_does_not_reinstate_a_node_with_another_standing_proof():
    coord, _, _ = _cluster()
    ok, _ = coord.inject_canary_audit("n1", "snap_lean4_algebra_v1", RW,
                                      expected_reward=0.99, expected_state_hash="00")
    assert ok is False
    coord._record_fault("n1", "unrelated protocol fault")
    assert coord.appeal_fraud(0) is True
    assert coord.fraud_proofs[0].kind == "overturned"
    assert coord.is_quarantined("n1")  # the protocol fault still stands


def test_appeal_reinstates_when_nothing_else_stands():
    coord, _, _ = _cluster()
    coord.inject_canary_audit("n1", "snap_lean4_algebra_v1", RW, expected_reward=0.99, expected_state_hash="00")
    assert coord.appeal_fraud(0) is True and not coord.is_quarantined("n1")


# =========================================================== phase 2: sandbox
def test_isinstance_with_metered_builtin_types_works_in_the_sandbox():
    sol = "def f(x):\n    return isinstance(x, (list, tuple)) and not isinstance(x, set)\n"
    tests = (
        "def test_types():\n    assert f([1]) and f((1,)) and not f({1})\n"
        "def test_methods():\n    l = list(range(3))\n    list.append(l, 9)\n    assert l == [0, 1, 2, 9]\n"
        "def test_sets():\n    assert isinstance(set([1]), set) and isinstance(frozenset(), frozenset)\n"
    )
    r = sandbox.run_test_job(sol, tests, ["test_types", "test_methods", "test_sets"])
    assert (r["passed"], r["total"], r["error"]) == (3, 3, None), r


@pytest.mark.parametrize("code", [
    "g = '{}'.format\n",
    "g = str.format_map\n",
    "match 1:\n    case str(__class__=k):\n        pass\n",
    "match 1:\n    case {**__rest}:\n        pass\n",
    "x = " + "+".join(["1"] * 5000) + "\n",
])
def test_static_policy_closes_address_and_dunder_bypasses(code):
    with pytest.raises(sandbox.SandboxPolicyError):
        sandbox.validate_code(code)


def test_direct_format_calls_are_still_allowed():
    sandbox.validate_code("s = '{}'.format(1)\nt = '{a}'.format_map({'a': 1})\n")


def test_bytes_formatting_is_address_scrubbed():
    r = sandbox.run_test_job("def f():\n    return b'%r' % (print,)\n",
                             "def test_a():\n    assert False, f()\n", ["test_a"])
    assert "at 0x?>" in r["failures"][0], r


def test_deeply_nested_code_is_a_validation_error_not_a_node_crash():
    node = SRPProviderNode(node_id="n_deep", ram_capacity_mb=64)
    node.pin_snapshot(M["code"])
    bid = node.fork(M["code"].snapshot_id)[0][0].branch_id
    r = node.step(bid, ActionPayload("apply_patch", {"code": "x = " + "+".join(["1"] * 5000) + "\n"}))
    # Two valid rejections: the AST depth limit, or (where the interpreter's own
    # parser gives up first, e.g. CPython 3.12 on Windows) a caught RecursionError.
    stderr = r.observation.stderr
    assert r.reward == 0.0 and stderr.startswith("Validation Error")
    assert "depth" in stderr or "deeply nested" in stderr
    assert node.arena.get_branch(bid).read_file("solution.py") == M["code"].initial_files["solution.py"]


# ============================================= phase 3: coordinator robustness
class _ArenaFreeProxy:
    """Duck-types the node API like RemoteNode does: no `.arena`."""

    def __init__(self, inner):
        self._n = inner
        self.node_id = inner.node_id

    def __getattr__(self, name):
        if name == "arena":
            raise AttributeError(name)
        return getattr(self._n, name)


def test_an_auditor_without_local_arena_access_still_catches_fraud():
    coord, node, _ = _cluster(audit_rate=1.0)
    coord.add_auditor(_ArenaFreeProxy(SRPProviderNode(node_id="aud_remote", ram_capacity_mb=128)))
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    coord.step(bid, RW)
    assert coord.audits_inconclusive == 0 and coord.audit_errors == 0
    _tamper_reward(node, step_index=2, value=1.0)
    with pytest.raises(PermissionError, match="Replay audit"):
        coord.step(bid, ActionPayload("apply_tactic", {"tactic": "invalid"}))


def test_coordinator_audit_errors_are_counted_and_visible():
    coord, _, _ = _cluster(audit_rate=1.0)
    auditor = next(iter(coord._auditors.values()))

    def broken(*a, **k):
        raise RuntimeError("auditor offline")

    auditor.run = broken
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    coord.step(bid, RW)
    telemetry = coord.cluster_telemetry()
    assert telemetry["replay_audit_errors"] == 1 and "auditor offline" in telemetry["last_audit_error"]
    assert not coord.is_quarantined("n1")


def test_a_failed_pin_on_one_node_still_records_the_nodes_that_pinned():
    coord = SRPCoordinator(canary_rate=0.0)
    good = SRPProviderNode(node_id="good", ram_capacity_mb=64)
    bad = SRPProviderNode(node_id="bad", ram_capacity_mb=64)
    coord.register_node(good)
    coord.register_node(bad)

    def full(manifest):
        raise MemoryError("full")

    bad.pin_snapshot = full
    with pytest.raises(MemoryError):
        coord.broadcast_snapshot(M["math"])
    assert coord._snapshot_holders["snap_lean4_algebra_v1"] == ["good"]
    assert coord.fork("snap_lean4_algebra_v1")[0]  # still routable to the node that pinned


def test_reaping_forgets_expired_branches_without_probing_every_branch():
    coord, node, _ = _cluster()
    calls = {"n": 0}
    real_has = node.has_branch

    def counting_has(bid):
        calls["n"] += 1
        return real_has(bid)

    node.has_branch = counting_has
    keep = coord.fork("snap_lean4_algebra_v1")[0][0]
    short = coord.fork("snap_lean4_algebra_v1", ttl_seconds=0.01)[0][0]
    time.sleep(0.05)
    assert coord.reap_expired_branches() == 1
    assert short not in coord._branch_to_node and keep in coord._branch_to_node
    assert calls["n"] == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_state_file_is_owner_only(tmp_path):
    path = tmp_path / "coord.json"
    SRPCoordinator(state_path=str(path), canary_rate=0.0)
    assert (path.stat().st_mode & 0o777) == 0o600


def test_remote_step_deadline_covers_the_sandbox_backstop():
    from srp.transport.http import RemoteNode

    remote = object.__new__(RemoteNode)
    remote.timeout_s, seen = 30.0, {}

    def fake_call(method, params, timeout_s=None):
        seen["timeout"] = timeout_s
        raise RuntimeError("stop")

    remote._call = fake_call
    with pytest.raises(RuntimeError):
        remote.step("b", ActionPayload("x", {}), timeout_ms=60_000)
    assert seen["timeout"] >= sandbox.backstop_ms(60_000) / 1000.0


# ========================================= phase 4: determinism and identity
def test_runtime_profile_names_the_cpu_architecture():
    import platform
    from srp.protocol.messages import current_runtime_profile

    assert current_runtime_profile().split("-")[-1] in {platform.machine().lower(), "x86_64", "aarch64"}


def test_same_files_with_a_different_suite_is_a_different_snapshot():
    coord, node, _ = _cluster()
    clash = SnapshotManifest(M["math"].snapshot_id, "srp-env-web", initial_files=dict(M["math"].initial_files))
    assert clash.content_merkle_root == M["math"].content_merkle_root
    with pytest.raises(ValueError, match="suite"):
        coord.broadcast_snapshot(clash)
    with pytest.raises(ValueError, match="suite"):
        node.pin_snapshot(clash)


def test_fraud_proof_replay_requires_the_same_manifest_identity():
    coord, node, _ = _cluster(audit_rate=1.0)
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    _tamper_reward(node, step_index=1, value=1.0)
    with pytest.raises(PermissionError):
        coord.step(bid, ActionPayload("apply_tactic", {"tactic": "invalid"}))
    fp = coord.fraud_proofs[-1]
    assert fp.root_manifest_digest == M["math"].identity_digest
    assert verify_fraud_proof_by_replay(fp, M["math"])
    other = SnapshotManifest(M["math"].snapshot_id, M["math"].suite, runtime="container_tmpfs",
                             initial_files=dict(M["math"].initial_files))
    assert not verify_fraud_proof_by_replay(fp, other)


def test_cad_sampling_uses_an_exact_integer_cube_root():
    from srp.envs.spatial_cad import _icbrt

    assert [_icbrt(n) for n in (0, 7, 8, 26, 27, 63_999, 64_000)] == [0, 1, 2, 2, 3, 39, 40]


# ================================================= phase 5: low severity
def test_an_action_with_a_lone_surrogate_is_rejected_before_dispatch():
    coord, node, _ = _cluster()
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    with pytest.raises(ValueError, match="not valid"):
        coord.step(bid, ActionPayload("apply_tactic", {"tactic": "\ud800"}))
    assert not coord.is_quarantined("n1") and coord.step(bid, RW).reward == 0.1
    nb = node.fork("snap_lean4_algebra_v1")[0][0].branch_id
    with pytest.raises(ValueError):
        node.step(nb, ActionPayload("apply_tactic", {"tactic": "\ud800"}))


@pytest.mark.parametrize("amount", [float("nan"), float("inf"), 0.0, -1.0])
def test_stake_amounts_must_be_positive_and_finite(amount):
    ledger = FiatAndApiCreditLedger()
    with pytest.raises(ValueError):
        ledger.deposit_stake("n", amount)
    ledger.deposit_stake("n", 5.0)
    with pytest.raises(ValueError):
        ledger.request_unbond("n", amount)


def test_ring_does_not_strip_function_application_parentheses():
    from srp.envs.math_lean import MathLeanVerifier

    check = MathLeanVerifier._check_builtin_algebraic_tactic
    assert not check("a+f(b+c)=f(b)+a+c", "ring")
    assert not check("(a+b)c=c+a+b", "ring")
    assert check("a + (b + c) = c + b + a", "ring")


def test_canonical_json_refuses_non_json_values():
    from srp.protocol.messages import canonical_json

    with pytest.raises(TypeError):
        canonical_json({"f": print})


def test_timeout_strikes_are_persisted_immediately(tmp_path):
    path = tmp_path / "state.json"
    coord, node, _ = _cluster(state_path=str(path), timeout_strike_limit=5)
    honest = node.step

    def claim_timeout(branch_id, action, request_id=None, timeout_ms=5000):
        res = honest(branch_id, action, request_id=request_id, timeout_ms=timeout_ms)
        res.observation.structured_data = {**res.observation.structured_data, "timed_out": True}
        res.reward = res.receipt.reward = 0.0
        res.receipt.observation_hash = res.observation.canonical_hash(res.truncated)
        res.receipt.sign(node._keypair)
        return res

    node.step = claim_timeout
    bid = coord.fork("snap_swe_sorting_v1")[0][0]
    coord.step(bid, ActionPayload("apply_patch", {"code": "def merge_intervals(x):\n    return x\n"}))
    assert json.loads(path.read_text())["timeout_strikes"] == {"n1": 1}


def test_appeal_refunds_each_part_of_a_slash_where_it_came_from():
    coord, _, ledger = _cluster(stake=30.0)
    acct = ledger.get_account("n1")
    ledger.record_verified_step("n1", 1.0, 0)  # some unsettled balance to slash first
    balance_before = acct.balance_units
    coord.inject_canary_audit("n1", "snap_lean4_algebra_v1", RW, expected_reward=0.99, expected_state_hash="00")
    assert coord.appeal_fraud(0) is True
    assert abs(acct.stake_units - 30.0) < 1e-9 and acct.slashed_units == 0.0
    assert acct.balance_units >= balance_before
