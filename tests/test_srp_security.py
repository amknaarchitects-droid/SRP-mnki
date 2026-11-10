"""
Security & integrity regression tests (SRP v0.3.0).
Each test names the audit finding it pins down. Tests that need Linux kernel
features return early elsewhere (they are exercised in CI on Linux).
"""

from __future__ import annotations

import json
import math
import os
import platform
import shutil
import tempfile
import threading
import time
import urllib.request

import pytest

from srp.cli import build_default_manifests
from srp.coordinator.server import SRPCoordinator, verify_fraud_proof_by_replay
from srp.envs import sandbox
from srp.node.daemon import SRPProviderNode
from srp.node.ram_arena import PAGE_SIZE, VolatileRAMArena
from srp.protocol import crypto
from srp.protocol.messages import ActionPayload, FraudProof, MemoryPingResponse, SnapshotManifest
from srp.protocol.residency import BallastCheckpoints, answer_chain
from srp.protocol.wire import WireError, decode_message, encode_message
from srp.settlement.base import FiatAndApiCreditLedger, TokenEscrowLedger, payout_leaf

IS_LINUX = platform.system() == "Linux"


def _cluster(audit_rate: float = 0.0, ledger=None, node_id: str = "n1", **kw):
    ledger = ledger or FiatAndApiCreditLedger()
    kw.setdefault("canary_rate", 0.0)
    coord = SRPCoordinator(settlement_provider=ledger, audit_rate=audit_rate, **kw)
    node = SRPProviderNode(node_id=node_id, ram_capacity_mb=64)
    coord.register_node(node)
    for m in build_default_manifests().values():
        coord.broadcast_snapshot(m)
    return coord, node, ledger


def _tamper(node: SRPProviderNode, when=lambda res: True, mutate=None, resign=True):
    """Wrap node.step: optionally mutate the honest result, then (re)sign consistently."""
    honest = node.step

    def step(branch_id, action, request_id=None, timeout_ms=5000):
        res = honest(branch_id, action, request_id=request_id, timeout_ms=timeout_ms)
        if when(res) and mutate is not None:
            mutate(res)
            if resign:
                res.receipt.reward = res.reward
                res.receipt.observation_hash = res.observation.canonical_hash(res.truncated)
                res.receipt.stdout_hash = crypto.hashlib.sha256(res.observation.stdout.encode()).hexdigest()
                res.receipt.step_dirty_pages = res.metrics.step_dirty_pages
                res.receipt.sign(node._keypair)
        return res

    node.step = step


def _fake_reward(value):
    def m(res):
        res.reward = value
    return m


# =============================================================== sandbox
def test_S1_generator_frame_escape_blocked_end_to_end():
    coord, _, _ = _cluster()
    bid = coord.fork("snap_swe_sorting_v1")[0][0]
    escape = (
        "def g():\n    yield gen.gi_frame.f_back\n"
        "gen = g()\nfor f in gen:\n    break\nprint('ESCAPED')\n"
        "def merge_intervals(x):\n    return x\n"
    )
    r = coord.step(bid, ActionPayload("apply_patch", {"code": escape}))
    assert r.reward == 0.0 and "ESCAPED" not in r.observation.stdout and "blocked" in r.observation.stderr


@pytest.mark.parametrize(
    "code",
    [
        "x = {}['__builtins__']", "class A:\n    pass\n", "async def f():\n    pass\n", "import os",
        "def f(e):\n    return e.tb_frame\n", "def __eq__(a, b):\n    return True\n",
        "try:\n    pass\nexcept:\n    pass\n", "def f():\n    global x\n",
    ],
)
def test_S1_static_policy_rejects_escape_vectors(code):
    with pytest.raises(sandbox.SandboxPolicyError):
        sandbox.validate_code(code)


def test_S1_audit_hook_blocks_even_if_static_policy_is_bypassed():
    """Defence in depth: disable layer 1 and the in-child audit hook still refuses."""
    orig_validate, orig_prepare = sandbox.validate_code, sandbox.prepare_source
    try:
        sandbox.validate_code = lambda code: __import__("ast").parse(code)
        sandbox.prepare_source = lambda tree: __import__("ast").unparse(tree)
        # Frame access needs no builtin: only the audit hook can stop it here
        frame = sandbox.run_test_job("def g():\n    yield 1\nx = g()\ny = x.gi_frame\n",
                                     "def test_a():\n    pass\n", ["test_a"])
        assert "operation 'object.__getattr__' is not permitted" in frame["error"]
        for payload in ("import os\nos.getpid()\n", "open('srp_should_not_exist.txt', 'w')\n"):
            res = sandbox.run_test_job(payload, "def test_a():\n    pass\n", ["test_a"])
            assert res["error"] and any(t in res["error"] for t in ("not permitted", "NameError", "ImportError"))
        assert not os.path.exists("srp_should_not_exist.txt")
    finally:
        sandbox.validate_code, sandbox.prepare_source = orig_validate, orig_prepare


def test_S1_linux_kernel_layers_block_network_process_and_writes():
    if not IS_LINUX:
        return
    import subprocess
    import sys

    probe = (
        sandbox._CHILD_PROGRAM.split("def _run():")[0]
        + "import json, os, socket\n"
        + "_apply_seccomp([tuple(i) for i in json.loads(%r)])\n" % json.dumps(sandbox.seccomp_program_x86_64())
        + "out = {}\n"
        + "for name, fn in [('socket', lambda: socket.socket()), ('fork', lambda: os.fork()),\n"
        + "                 ('open_w', lambda: open('/tmp/srp_probe_w', 'w')), ('exec', lambda: os.execv('/bin/true', ['t']))]:\n"
        + "    try:\n        fn(); out[name] = 'ALLOWED'\n    except OSError as e:\n        out[name] = e.errno\n"
        + "print(json.dumps(out))\n"
    )
    r = subprocess.run([sys.executable, "-I", "-S", "-c", probe], capture_output=True, text=True, timeout=30)
    assert json.loads(r.stdout) == {"socket": 1, "fork": 1, "open_w": 1, "exec": 1}
    net = subprocess.run(
        [sys.executable, "-I", "-S", "-c",
         "import socket\ns=socket.socket(); s.settimeout(2)\n"
         "try:\n    s.connect(('1.1.1.1', 80)); print('OPEN')\nexcept OSError as e:\n    print('BLOCKED')\n"],
        preexec_fn=sandbox._linux_preexec(256, 5), capture_output=True, text=True, timeout=30,
    )
    assert net.stdout.strip() == "BLOCKED"
    assert sandbox.isolation_report()["kernel_network_isolation"] is True


def test_S_builtin_shadowing_cannot_fake_test_success():
    res = sandbox.run_test_job(
        "def solve():\n    return [1, 2, 3]\ndef sum(x):\n    return 100\ndef max(x):\n    return 42\n",
        "def test_a():\n    assert sum(solve()) == 100\ndef test_b():\n    assert max(solve()) == 42\n",
        ["test_a", "test_b"],
    )
    assert res["passed"] == 0 and res["total"] == 2


def test_S_memory_addresses_are_scrubbed_and_output_is_deterministic():
    code = "def g():\n    return 1\nprint(g, f'{g}', '%s' % g, '{}'.format(g), str([g]))\n"
    runs = [sandbox.run_test_job(code, "def test_a():\n    assert g() == 1\n", ["test_a"]) for _ in range(2)]
    assert runs[0]["stdout"] == runs[1]["stdout"] and "0x?" in runs[0]["stdout"]
    assert all(r["passed"] == 1 for r in runs)


def test_S3_fuel_makes_runaway_code_deterministic():
    for code in ("while True:\n    pass\n", "s = sum(range(10 ** 9))\n"):
        a = sandbox.run_test_job(code, "def test_a():\n    pass\n", ["test_a"], timeout_ms=400)
        b = sandbox.run_test_job(code, "def test_a():\n    pass\n", ["test_a"], timeout_ms=400)
        assert a["fuel_exhausted"] and not a["timed_out"]
        assert (a["error"], a["fuel_used"]) == (b["error"], b["fuel_used"])
    big = sandbox.run_test_job("x = 10 ** (10 ** 8)\n", "def test_a():\n    pass\n", ["test_a"])
    assert big["error"].startswith("OverflowError")


def test_S3_memory_bomb_is_capped():
    coord, _, _ = _cluster()
    bid = coord.fork("snap_swe_sorting_v1")[0][0]
    r = coord.step(bid, ActionPayload("apply_patch", {"code": "x = 'a' * (2 * 1024 ** 3)\n"}))
    assert r.reward == 0.0 and r.observation.exit_code == 1


def test_S_hidden_test_file_is_not_readable_by_the_agent():
    coord, _, _ = _cluster()
    bid = coord.fork("snap_swe_sorting_v1")[0][0]
    r = coord.step(bid, ActionPayload("read_file", {"path": "test_suite.py"}))
    assert r.observation.stdout == "" and "not readable" in r.observation.stderr


# ===================================================== CAD / reward farming
def test_S4_phantom_subtraction_and_overlap_cannot_game_cad_reward():
    coord, _, _ = _cluster()
    bid = coord.fork("snap_cad_pedestal_v1")[0][0]
    phantom = [
        {"type": "box", "center": [0.0, 0.0, 6.0], "size": [10.0, 10.0, 12.0]},
        {"type": "box", "center": [500.0, 0.0, 6.0], "size": [5.0, 2.0, 10.0], "operation": "subtract"},
        {"type": "box", "center": [-500.0, 0.0, 6.0], "size": [5.0, 2.0, 10.0], "operation": "subtract"},
    ]
    r = coord.step(bid, ActionPayload("set_assembly", {"primitives": phantom}))
    assert r.observation.structured_data["net_volume"] == 1200.0 and r.terminated is False


def test_S5_completion_rewards_are_paid_once():
    coord, _, _ = _cluster()
    mb = coord.fork("snap_lean4_algebra_v1")[0][0]
    coord.step(mb, ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"}))
    assert coord.step(mb, ActionPayload("apply_tactic", {"tactic": "omega"})).reward == 1.0
    again = coord.step(mb, ActionPayload("apply_tactic", {"tactic": "omega"}))
    assert again.reward == 0.0 and again.terminated is True


# ============================================================ receipts (L1)
def test_unsigned_observation_fields_can_no_longer_be_forged():
    coord, node, ledger = _cluster()
    bid = coord.fork("snap_swe_sorting_v1")[0][0]

    def forge(res):
        res.observation.stderr = "FORGED"
        res.observation.structured_data = {"passed": 99}
        res.metrics.step_dirty_pages = 10 ** 9

    _tamper(node, mutate=forge, resign=False)
    with pytest.raises(PermissionError, match="observation_hash|step_dirty_pages"):
        coord.step(bid, ActionPayload("apply_patch", {"code": "def merge_intervals(x):\n    return x\n"}))
    assert ledger.get_account("n1").balance_units == 0.0
    assert coord.is_quarantined("n1")
    assert coord.fraud_proofs[-1].kind == "protocol_fault" and not coord.fraud_proofs[-1].slashable


def test_non_finite_reward_is_rejected():
    coord, node, _ = _cluster()
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    _tamper(node, mutate=_fake_reward(float("nan")), resign=False)
    with pytest.raises(PermissionError, match="Non-finite"):
        coord.step(bid, ActionPayload("apply_tactic", {"tactic": "rfl"}))


def test_V6_replayed_receipt_is_rejected():
    coord, node, _ = _cluster()
    bid = coord.fork("snap_web_checkout_v1")[0][0]
    first = coord.step(bid, ActionPayload("observe_dom", {}))
    node.step = lambda *a, **k: first
    with pytest.raises(PermissionError, match="request_id"):
        coord.step(bid, ActionPayload("observe_dom", {}))


def test_fork_reply_cannot_hijack_branch_ids():
    coord, node, _ = _cluster()
    victim = coord.fork("snap_web_checkout_v1")[0][0]
    honest_fork = node.fork

    def hijack(source_id, count=1, ttl_seconds=None, branch_ids=None):
        branches, ms = honest_fork(source_id, count, ttl_seconds=ttl_seconds)  # ignores minted ids
        return branches, ms

    node.fork = hijack
    with pytest.raises(PermissionError, match="minted"):
        coord.fork("snap_web_checkout_v1")
    assert coord._branch_to_node.get(victim) == "n1"


def test_V4_receipts_are_ed25519_and_unforgeable():
    coord, node, _ = _cluster()
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    rec = coord.step(bid, ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"})).receipt
    assert rec.verify_signature(node.public_key_hex)
    rec.step_dirty_pages += 1
    assert not rec.verify_signature(node.public_key_hex)
    rec.sign(crypto.NodeKeypair.generate())
    assert not rec.verify_signature(node.public_key_hex)


# ============================================================ audits (L2)
def test_V1_lazy_node_is_caught_and_slashed_with_a_replayable_proof():
    coord, node, ledger = _cluster(audit_rate=1.0)
    ledger.deposit_stake("n1", 50.0)
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    _tamper(node, mutate=_fake_reward(1.0))
    with pytest.raises(PermissionError, match="Replay audit"):
        coord.step(bid, ActionPayload("apply_tactic", {"tactic": "invalid_tactic"}))
    fp = coord.fraud_proofs[-1]
    assert fp.slashable and fp.lineage and fp.root_content_hash
    assert verify_fraud_proof_by_replay(fp, build_default_manifests()["math"])
    acct = ledger.get_account("n1")
    assert acct.verified_steps == 0 and acct.stake_units == 40.0
    assert coord.is_quarantined("n1")


def test_rewarded_steps_are_always_audited_even_at_zero_audit_rate():
    coord, node, _ = _cluster(audit_rate=0.0)
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    _tamper(node, mutate=_fake_reward(1.0))
    with pytest.raises(PermissionError):
        coord.step(bid, ActionPayload("apply_tactic", {"tactic": "invalid_tactic"}))


def test_a_lie_on_an_unaudited_step_is_caught_by_a_later_audit():
    coord, node, _ = _cluster(audit_rate=0.0, audit_rewarded_steps=False)
    bid = coord.fork("snap_web_checkout_v1")[0][0]
    _tamper(node, when=lambda res: res.receipt.step_index == 2, mutate=_fake_reward(0.77))
    coord.step(bid, ActionPayload("fill_input", {"selector": "#coupon-input", "value": "X"}))
    assert coord.step(bid, ActionPayload("click", {"selector": "#apply-btn"})).reward == 0.77  # unaudited lie
    coord.audit_rate = 1.0
    with pytest.raises(PermissionError, match="committed step 2"):
        coord.step(bid, ActionPayload("observe_dom", {}))
    assert verify_fraud_proof_by_replay(coord.fraud_proofs[-1], build_default_manifests()["web"])


def test_audit_failures_on_the_coordinator_never_frame_honest_nodes():
    coord, node, _ = _cluster(audit_rate=1.0)
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    auditor = next(iter(coord._auditors.values()))
    real_run, calls = auditor.run, {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise MemoryError("auditor arena full")
        return real_run(*a, **k)

    auditor.run = flaky
    coord.step(bid, ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"}))
    assert coord.step(bid, ActionPayload("apply_tactic", {"tactic": "omega"})).reward == 1.0
    assert coord.fraud_proofs == [] and not coord.is_quarantined("n1")


def test_incremental_audits_do_not_replay_the_whole_rollout():
    coord, _, _ = _cluster(audit_rate=1.0)
    bid = coord.fork("snap_web_checkout_v1")[0][0]
    auditor = next(iter(coord._auditors.values())).node
    n = 120
    for i in range(n):
        coord.step(bid, ActionPayload("fill_input", {"selector": "#coupon-input", "value": f"v{i}"}))
    # Quadratic replay would be ~n^2/2 = 7200 auditor steps
    assert auditor.steps_executed <= 2 * n
    assert coord.fraud_proofs == []


def test_false_timeout_claims_earn_nothing_close_the_branch_and_accumulate_strikes():
    coord, node, ledger = _cluster(audit_rate=0.0, timeout_strike_limit=2)

    def claim_timeout(res):
        res.reward = 0.0
        res.observation.structured_data = {**res.observation.structured_data, "timed_out": True}

    _tamper(node, mutate=claim_timeout)
    code = {"code": "def merge_intervals(x):\n    return x\n"}
    for _ in range(2):
        bid = coord.fork("snap_swe_sorting_v1")[0][0]
        coord.step(bid, ActionPayload("apply_patch", code))
        with pytest.raises(KeyError, match="closed"):
            coord.step(bid, ActionPayload("apply_patch", code))
    assert ledger.get_account("n1").verified_steps == 0
    assert coord.is_quarantined("n1")
    assert not any(fp.slashable for fp in coord.fraud_proofs)


def test_V2_canaries_run_at_depth_through_the_normal_path():
    coord, node, _ = _cluster()
    mb = coord.fork("snap_lean4_algebra_v1")[0][0]
    coord.step(mb, ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"}))
    coord.register_canary("snap_lean4_algebra_v1", ActionPayload("apply_tactic", {"tactic": "omega"}))
    assert coord.run_canary_round() == [("n1", True)]
    _tamper(node, when=lambda res: res.receipt.step_index >= 2, mutate=_fake_reward(0.5))
    ok, fp = coord.inject_canary_audit(
        "n1", "snap_lean4_algebra_v1", ActionPayload("apply_tactic", {"tactic": "omega"}),
        prefix=[(ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"}), 5000)],
    )
    assert ok is False and fp is not None and fp.slashable
    assert node.arena.stats()["active_branches"] == 1  # only the trainer's branch remains


def test_wrongly_framed_node_wins_its_appeal_and_is_refunded():
    coord, node, ledger = _cluster()
    ledger.deposit_stake("n1", 30.0)
    ok, fp = coord.inject_canary_audit(
        "n1", "snap_lean4_algebra_v1", ActionPayload("apply_tactic", {"tactic": "rfl"}), expected_reward=1.0
    )
    slashed_stake = ledger.stake_of("n1")
    assert ok is False and coord.is_quarantined("n1") and slashed_stake < 20.01
    assert coord.appeal_fraud(coord.fraud_proofs.index(fp)) is True
    assert not coord.is_quarantined("n1") and abs(ledger.stake_of("n1") - (slashed_stake + 10.0)) < 1e-9
    assert coord.fraud_proofs[-1].kind == "overturned"


# ======================================================= residency (L3)
def test_V3_chained_residency_rejects_public_data_and_slow_or_regenerating_nodes():
    coord, node, _ = _cluster(ping_rounds=256)
    assert coord.verify_node_ram_residency("n1", "snap_swe_sorting_v1")[0] is True
    real = node.handle_memory_ping

    # (a) answers from public manifest data with fake ballast
    def public_only(ch):
        resp = real(ch)
        return MemoryPingResponse(resp.challenge_id, resp.node_id, resp.snapshot_id,
                                  resp.sampled_page_indices, resp.combined_digest, resp.elapsed_ms,
                                  ["00" * 32] * len(resp.page_hashes))

    node.handle_memory_ping = public_only
    assert coord.verify_node_ram_residency("n1", "snap_swe_sorting_v1")[0] is False

    # (b) drops ballast, keeps 1/32 checkpoints and regenerates on demand
    spec = coord._ballast[("n1", "snap_swe_sorting_v1")]
    sparse = BallastCheckpoints(spec.seed, spec.count, stride=32)
    snap = node.arena._snapshots["snap_swe_sorting_v1"]

    def regenerating(ch):
        def read(pool, idx):
            return sparse.page(idx) if pool == "b" else node.arena._base_pages[snap.ordered_page_hashes[idx]]
        idx, hashes, digest = answer_chain(ch.nonce, ch.sample_page_count, snap.page_count, spec.count, read)
        return MemoryPingResponse(ch.challenge_id, node.node_id, ch.snapshot_id, idx, digest, 0.0, hashes)

    node.handle_memory_ping = regenerating
    ok, _ = coord.verify_node_ram_residency("n1", "snap_swe_sorting_v1")
    assert ok is False  # cryptographically valid, but far too slow per lookup


def test_E2_lease_pays_only_verified_ballast_and_never_quarantined_nodes():
    ledger = FiatAndApiCreditLedger(rate_per_gb_hour=1e7)
    coord, node, _ = _cluster(ledger=ledger)
    assert ledger.get_account("n1").balance_units == 0.0
    time.sleep(0.05)
    assert coord.verify_node_ram_residency("n1", "snap_lean4_algebra_v1")[0] is True
    earned = ledger.get_account("n1").pinned_gb_hours
    spec = coord._ballast[("n1", "snap_lean4_algebra_v1")]
    assert earned <= (spec.count * PAGE_SIZE / 1024 ** 3) * (1.0 / 3600)  # ballast bytes only
    coord._quarantine("n1")
    assert coord.verify_node_ram_residency("n1", "snap_lean4_algebra_v1") == (False, 0.0)


# ================================================== identity / persistence
def test_V5_quarantine_binds_the_key_and_survives_restart():
    tmp = tempfile.mkdtemp()
    try:
        path = os.path.join(tmp, "coord_state.json")
        secret = b"\x07" * 32
        coord = SRPCoordinator(canary_rate=0.0, state_path=path, master_secret=secret)
        node = SRPProviderNode(node_id="bad1", ram_capacity_mb=16, node_secret="k" * 64)
        coord.register_node(node)
        coord.register_node(SRPProviderNode(node_id="good1", ram_capacity_mb=16, node_secret="g" * 64))
        coord._record_fault("bad1", "test fault")
        same_key_new_id = SRPProviderNode(node_id="bad1_v2", ram_capacity_mb=16, node_secret="k" * 64)
        with pytest.raises(PermissionError, match="quarantined"):
            coord.register_node(same_key_new_id)
        restarted = SRPCoordinator(canary_rate=0.0, state_path=path)
        with pytest.raises(PermissionError, match="quarantined"):
            restarted.register_node(node)
        assert restarted._master == secret and restarted.keypair.public_key_hex == coord.keypair.public_key_hex
        with pytest.raises(PermissionError, match="different public key"):
            restarted.register_node(SRPProviderNode(node_id="good1", ram_capacity_mb=16))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_runtime_profile_without_auditor_and_missing_kernel_isolation_are_refused():
    coord = SRPCoordinator(canary_rate=0.0)
    node = SRPProviderNode(node_id="odd", ram_capacity_mb=16)
    real_caps = node.capabilities

    def caps():
        c = real_caps()
        c.runtime_profile = "cpython-3.99-siphash13-plan9"
        return c

    node.capabilities = caps
    with pytest.raises(PermissionError, match="runtime profile"):
        coord.register_node(node)
    strict = SRPCoordinator(canary_rate=0.0, require_kernel_isolation=True)
    honest = SRPProviderNode(node_id="h", ram_capacity_mb=16)
    if IS_LINUX:
        strict.register_node(honest)
    else:
        with pytest.raises(PermissionError, match="kernel-level"):
            strict.register_node(honest)


# ================================================================ economics
def test_slashing_needs_verifiable_proof_and_uses_unsettled_then_stake():
    ledger = TokenEscrowLedger(rate_per_step=10.0)
    with pytest.raises(ValueError):
        ledger.record_canary_failure("x", FraudProof("x", "r", "bare", 0, 1))
    coord, node, _ = _cluster(ledger=ledger, audit_rate=1.0)
    ledger.deposit_stake("n1", 10.0)
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    coord.step(bid, ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"}))
    ledger.close_epoch()  # earnings paid out
    paid = ledger.get_account("n1").settled_units
    _tamper(node, mutate=_fake_reward(1.0))
    with pytest.raises(PermissionError):
        coord.step(bid, ActionPayload("apply_tactic", {"tactic": "invalid_tactic"}))
    acct = ledger.get_account("n1")
    assert acct.settled_units == paid and acct.balance_units == paid  # no clawback of paid earnings
    assert acct.stake_units == 0.0 and acct.slashed_units == 10.0


def test_unbonding_stake_stays_slashable_until_released():
    ledger = FiatAndApiCreditLedger(slash_penalty_units=5.0)
    ledger.unbonding_period_s = 0.05
    ledger.deposit_stake("u", 8.0)
    ledger.request_unbond("u", 8.0)
    assert ledger.stake_of("u") == 0.0 and ledger.get_account("u").bonded_units == 8.0
    fp = FraudProof("u", "r", "x", 0, 1)
    fp.__class__ = type("Slashable", (FraudProof,), {"slashable": property(lambda self: True)})
    ledger.record_canary_failure("u", fp)
    assert ledger.get_account("u").bonded_units == 3.0
    time.sleep(0.06)
    assert ledger.withdraw_unbonded("u") == 3.0


def test_E3_epoch_payout_roots_cover_only_new_amounts():
    ledger = TokenEscrowLedger(rate_per_step=1.0)
    ledger.record_verified_step("node:a", compute_ms=1, dirty_pages=0)
    e1 = ledger.close_epoch()
    assert e1.leaves == [("node:a", 1_000_000)] and ledger.close_epoch().leaves == []
    assert payout_leaf(1, "a:b", 1, "T") != payout_leaf(1, "a", 1, "b:T")


# ===================================================================== arena
def test_concurrent_snapshot_evictions_and_pins_are_safe():
    arena = VolatileRAMArena(capacity_mb=8)
    arena.pin_snapshot(SnapshotManifest("s", "srp-env-code", "wasm_cow", {"f": "x"}))
    arena.fork("s")
    real_evict = arena.evict_branch

    def slow_evict(bid):
        time.sleep(0.1)
        return real_evict(bid)

    arena.evict_branch = slow_evict
    errors, results = [], []

    def go():
        try:
            results.append(arena.evict_snapshot("s"))
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=go) for _ in range(3)]
    for t in threads:
        t.start()
    time.sleep(0.03)
    with pytest.raises(RuntimeError, match="being evicted"):
        arena.pin_snapshot(SnapshotManifest("s", "srp-env-code", "wasm_cow", {"f": "x"}))
    for t in threads:
        t.join()
    assert errors == [] and sorted(results)[-1] > 0 and arena.used_ram_bytes == 0


def test_snapshot_metadata_is_charged_and_refunded():
    arena = VolatileRAMArena(capacity_mb=8)
    arena.pin_snapshot(SnapshotManifest("s", "srp-env-code", "wasm_cow", {"a": "1", "b": "2"}))
    assert arena.metadata_ram_bytes > 0
    arena.evict_snapshot("s")
    assert arena.metadata_ram_bytes == 0


def test_ttl_branches_expire_and_are_reaped():
    coord, node, _ = _cluster()
    bid = coord.fork("snap_web_checkout_v1", ttl_seconds=0.05)[0][0]
    time.sleep(0.1)
    with pytest.raises(KeyError):
        coord.step(bid, ActionPayload("observe_dom", {}))
    coord.fork("snap_web_checkout_v1", ttl_seconds=0.05)
    time.sleep(0.1)
    assert coord.reap_expired_branches() == 1 and coord._branch_to_node == {}


# ================================================================ wire / crypto
def test_wire_codec_roundtrip_preserves_signed_receipts():
    coord, node, _ = _cluster()
    bid = coord.fork("snap_lean4_algebra_v1")[0][0]
    res = coord.step(bid, ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"}))
    method, decoded, _ = decode_message(encode_message(res))
    assert method == "SRP_STEP_RESULT" and decoded == res
    assert decoded.receipt.verify_signature(node.public_key_hex)


@pytest.mark.parametrize(
    "body",
    [
        '{"source_id":["x"]}', '{"source_id":"s","branch_count":-5}', '{"source_id":"s","evil":1}',
        '{"source_id":"s","ttl_seconds":1e999}', '{"source_id":"s","branch_count":true}',
        '{"source_id":"s","branch_count":' + "9" * 500 + "}",
    ],
)
def test_wire_codec_rejects_malformed_frames(body):
    frame = '{"jsonrpc":"2.0","id":"1","method":"SRP_FORK","params":{"srp_version":"0.3.0","body":%s}}' % body
    with pytest.raises(WireError):
        decode_message(frame)
    with pytest.raises(WireError):
        decode_message("[" * 50_000 + "]" * 50_000)


@pytest.mark.parametrize("pure", [True, False])
def test_ed25519_matches_rfc8032_vector(pure):
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    kp = crypto.NodeKeypair(seed, force_pure_python=pure)
    assert kp.public_key_hex == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert kp.sign(b"") == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065"
        "224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )


# ================================================================ transport
def test_signed_http_transport_end_to_end_rejects_intruders_and_replays():
    from srp.transport import NodeServer, RemoteNode
    from srp.transport.http import _command_message

    coord = SRPCoordinator(canary_rate=0.0, audit_rate=1.0)
    node = SRPProviderNode(node_id="remote1", ram_capacity_mb=64)
    server = NodeServer(node, coord.keypair.public_key_hex).start()
    try:
        coord.register_node(RemoteNode(server.url, coord.keypair, node_id="remote1"))
        m = build_default_manifests()["math"]
        coord.broadcast_snapshot(m)
        bid = coord.fork(m.snapshot_id)[0][0]
        coord.step(bid, ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"}))
        assert coord.step(bid, ActionPayload("apply_tactic", {"tactic": "omega"})).reward == 1.0
        assert coord.verify_node_ram_residency("remote1", m.snapshot_id)[0] is True
        assert coord.fraud_proofs == []

        with pytest.raises(PermissionError):
            RemoteNode(server.url, crypto.NodeKeypair.generate(), node_id="remote1")

        ts, nonce = time.time(), "n" * 16
        frame = json.dumps({
            "jsonrpc": "2.0", "id": "r1", "method": "node.telemetry", "params": {},
            "auth": {"coordinator": coord.keypair.public_key_hex, "ts": ts, "nonce": nonce,
                     "sig": coord.keypair.sign(_command_message("remote1", "node.telemetry", {}, "r1", ts, nonce))},
        }).encode()
        codes = []
        for _ in range(2):
            try:
                urllib.request.urlopen(urllib.request.Request(server.url, data=frame,
                                       headers={"Content-Type": "application/json"}), timeout=5)
                codes.append(200)
            except urllib.error.HTTPError as exc:
                codes.append(exc.code)
        assert codes == [200, 409]
    finally:
        server.stop()
