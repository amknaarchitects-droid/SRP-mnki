"""
SRP Coordinator & Verification Mesh
===================================
Orchestrates snapshot pinning, snapshot-aware routing, GRPO/MCTS forking and
the SRP-003 verification layers:

  Layer 1  Ed25519 receipts (V3) bound to the coordinator's request, root
           snapshot, step index, parent state, timeout, full observation hash
           and billed metrics; checked against the coordinator's own view of
           each branch. Branch ids are minted by the coordinator.
  Layer 2  Blind replay audits on a trusted auditor with the same runtime
           profile. Audits are incremental (an LRU of auditor CoW checkpoints
           keyed by lineage digest), re-verify *every* committed step since the
           nearest checkpoint, always cover rewarded/terminal/timed-out steps,
           and require a mismatch to be confirmed by repeated auditor runs
           before anything counts as fraud. Canaries run at random depths
           through the ordinary path.
  Layer 3  Chained (pointer-chasing) residency challenges over time-memory-hard
           ballast, with an RTT baseline subtracted (`srp.protocol.residency`).

Fraud handling: only self-contained proofs (signed receipt + replayable lineage)
are slashed; any third party can re-check them with
`verify_fraud_proof_by_replay`. Protocol faults quarantine without slashing.
Quarantine binds the node id *and* public key, survives restarts (`state_path`),
and can be appealed (`appeal_fraud`).

Concurrency: per-branch coordinator lock -> coordinator._lock. Node calls are
never made while holding coordinator._lock.
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import json
import math
import os
import secrets
import statistics
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from srp.node.daemon import DEFAULT_STEP_TIMEOUT_MS, SRPProviderNode
from srp.node.ram_arena import PAGE_SIZE
from srp.protocol.crypto import NodeKeypair, registration_message, verify_signature
from srp.protocol.messages import (
    FRAUD_KIND_CANARY,
    FRAUD_KIND_REPLAY,
    ActionPayload,
    ExecutionReceipt,
    FraudProof,
    MemoryPingChallenge,
    SnapshotManifest,
    StepResult,
    current_runtime_profile,
    sha256_hex,
)
from srp.protocol.residency import BallastCheckpoints, verify_chain
from srp.settlement.base import FiatAndApiCreditLedger, SettlementProvider

PROTOCOL_VERSION = "0.3.0"


# --------------------------------------------------------------------------- #
# Lineage: an immutable cons-list of committed steps                           #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class _Cell:
    action_json: str
    timeout_ms: int
    receipt: ExecutionReceipt
    parent: Optional["_Cell"]
    digest: str
    depth: int


def _root_digest(root: str, content_hash: str) -> str:
    return sha256_hex(f"SRP_LINEAGE_ROOT|{root}|{content_hash}")


def _cell_digest(parent_digest: str, action_json: str, timeout_ms: int) -> str:
    return sha256_hex(f"SRP_LINEAGE|{parent_digest}|{timeout_ms}|{action_json}")


def _freeze_action(action: ActionPayload) -> str:
    return json.dumps(
        {"command": action.command, "payload": action.payload},
        sort_keys=True, separators=(",", ":"), allow_nan=False,
    )


def _thaw(action_json: str) -> ActionPayload:
    data = json.loads(action_json)
    return ActionPayload(command=data["command"], payload=data["payload"])


def _cells(lineage: Optional[_Cell]) -> List[_Cell]:
    out: List[_Cell] = []
    while lineage is not None:
        out.append(lineage)
        lineage = lineage.parent
    out.reverse()
    return out


def _timed_out(result: StepResult) -> bool:
    return bool(result.observation.structured_data.get("timed_out", False))


def _outcome(rec: ExecutionReceipt) -> Tuple:
    """Everything a trusted replay must reproduce exactly."""
    return (
        rec.parent_state_hash, rec.next_state_hash, rec.dirty_page_merkle_root,
        rec.stdout_hash, rec.observation_hash, f"{float(rec.reward):.8f}",
        bool(rec.terminated), bool(rec.truncated), int(rec.step_dirty_pages),
    )


# --------------------------------------------------------------------------- #
# Trusted auditor with an incremental checkpoint cache                         #
# --------------------------------------------------------------------------- #
class _Auditor:
    def __init__(self, node: SRPProviderNode, cache_size: int, timeout_ms: int) -> None:
        self.node = node
        self.profile = node.capabilities().runtime_profile
        self.cache_size = cache_size
        self.timeout_ms = timeout_ms
        self._lock = threading.Lock()
        self._cache: "collections.OrderedDict[str, str]" = collections.OrderedDict()
        self._cache_root: Dict[str, str] = {}

    def _ensure_pinned(self, manifest: SnapshotManifest) -> None:
        try:
            self.node.pin_snapshot(manifest)
        except MemoryError:
            self.drop_all()
            self.node.pin_snapshot(manifest)

    def drop_root(self, root: str) -> None:
        with self._lock:
            stale = [d for d, r in self._cache_root.items() if r == root]
            bids = [self._cache.pop(d) for d in stale if d in self._cache]
            for d in stale:
                self._cache_root.pop(d, None)
        for bid in bids:
            self.node.evict_branch(bid)
        try:
            self.node.evict_snapshot(root, evict_branches=True)
        except Exception:
            pass

    def drop_all(self) -> None:
        with self._lock:
            bids = list(self._cache.values())
            roots = set(self._cache_root.values())
            self._cache.clear()
            self._cache_root.clear()
        for bid in bids:
            self.node.evict_branch(bid)
        for snap in list(self.node.arena._snapshots):
            if snap not in roots:
                try:
                    self.node.evict_snapshot(snap)
                except Exception:
                    pass

    def _remember(self, digest: str, root: str, bid: str) -> None:
        evict: List[str] = []
        with self._lock:
            if digest in self._cache:
                evict.append(bid)
            else:
                self._cache[digest] = bid
                self._cache_root[digest] = root
                while len(self._cache) > self.cache_size:
                    old_digest, old_bid = self._cache.popitem(last=False)
                    self._cache_root.pop(old_digest, None)
                    evict.append(old_bid)
        for b in evict:
            self.node.evict_branch(b)

    def run(
        self,
        manifest: SnapshotManifest,
        history: List[_Cell],
        action: ActionPayload,
        timeout_ms: int,
        final_digest: Optional[str],
    ) -> Dict[str, Any]:
        """
        Re-execute `history` (verifying every committed receipt) and then `action`.
        Returns {"status": "ok"|"prefix_mismatch"|"indeterminate", ...}.
        """
        root = manifest.snapshot_id
        self._ensure_pinned(manifest)
        start, base_bid = 0, None
        with self._lock:
            for i in range(len(history) - 1, -1, -1):
                bid = self._cache.get(history[i].digest)
                if bid is not None and self.node.has_branch(bid):
                    self._cache.move_to_end(history[i].digest)
                    start, base_bid = i + 1, bid
                    break
        source = base_bid or root
        try:
            bid = self.node.fork(source, count=1)[0][0].branch_id
        except (KeyError, MemoryError):
            self.drop_all()
            self._ensure_pinned(manifest)
            start, bid = 0, self.node.fork(root, count=1)[0][0].branch_id
        keep = False
        try:
            for cell in history[start:]:
                truth = self.node.step(bid, _thaw(cell.action_json), timeout_ms=cell.timeout_ms)
                if _timed_out(truth):
                    return {"status": "indeterminate"}
                if _outcome(truth.receipt)[1:] != _outcome(cell.receipt)[1:]:
                    return {"status": "prefix_mismatch", "cell": cell, "truth": truth}
            before = self.node.arena.get_branch(bid).state_hash
            t0 = time.perf_counter()
            truth = self.node.step(bid, action, timeout_ms=timeout_ms)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if final_digest is not None and not _timed_out(truth):
                self._remember(final_digest, root, bid)
                keep = True
            return {"status": "ok", "before": before, "truth": truth, "elapsed_ms": elapsed_ms}
        finally:
            if not keep:
                self.node.evict_branch(bid)


def verify_fraud_proof_by_replay(
    fp: FraudProof, manifest: SnapshotManifest, runs: int = 2
) -> bool:
    """
    Independent check of a slashable FraudProof, runnable by anyone: confirms the
    node signed the receipt and that a deterministic replay of the recorded
    lineage (on this host, which must share the proof's runtime profile)
    contradicts it in every run. Returns True when the fraud is confirmed.
    """
    if not fp.is_third_party_verifiable():
        return False
    if manifest.snapshot_id != fp.root_snapshot_id or manifest.content_merkle_root != fp.root_content_hash:
        return False
    if fp.runtime_profile and fp.runtime_profile != current_runtime_profile():
        raise RuntimeError(f"Replay requires runtime profile {fp.runtime_profile}")
    steps = fp.lineage
    for _ in range(max(1, runs)):
        node = SRPProviderNode(node_id="srp_fraud_verifier", ram_capacity_mb=256)
        node.pin_snapshot(manifest)
        bid = node.fork(manifest.snapshot_id)[0][0].branch_id
        truth: Optional[StepResult] = None
        for step in steps:
            truth = node.step(bid, ActionPayload(step["command"], step["payload"]),
                              timeout_ms=int(step["timeout_ms"]))
        if truth is None or _timed_out(truth):
            return False
        if _outcome(truth.receipt)[1:] == _outcome(fp.receipt)[1:]:
            return False
    return True


@dataclass
class CanaryTask:
    snapshot_id: str
    action: ActionPayload
    expected_reward: Optional[float] = None
    expected_state_hash: Optional[str] = None


@dataclass
class _BallastSpec:
    seed: bytes
    count: int
    checkpoints: Optional[BallastCheckpoints] = None


class SRPCoordinator:
    """
    Coordinates SRPProviderNodes: routing, signed-receipt verification, blind
    incremental replay audits, canaries, residency challenges and settlement.
    """

    AUDITOR_NODE_ID = "srp_coordinator_auditor"

    def __init__(
        self,
        settlement_provider: Optional[SettlementProvider] = None,
        canary_rate: float = 0.05,
        audit_rate: Optional[float] = None,
        audit_rewarded_steps: bool = True,
        audit_confirm_runs: int = 2,
        audit_cache_size: int = 256,
        min_stake_units: float = 0.0,
        ballast_ratio: float = 0.25,
        min_ballast_pages: int = 64,
        ping_rounds: int = 512,
        ping_repeats: int = 3,
        ping_spot_checks: int = 32,
        max_lookup_us: float = 60.0,
        max_lease_interval_s: float = 3600.0,
        quarantine_on_fraud: bool = True,
        timeout_strike_limit: int = 3,
        max_billable_dirty_pages: int = 256,
        step_timeout_ms: int = DEFAULT_STEP_TIMEOUT_MS,
        require_kernel_isolation: bool = False,
        auditor_node: Optional[SRPProviderNode] = None,
        auditor_ram_mb: int = 512,
        master_secret: Optional[bytes] = None,
        keypair: Optional[NodeKeypair] = None,
        state_path: Optional[str] = None,
    ) -> None:
        for name, rate in (("canary_rate", canary_rate), ("audit_rate", audit_rate)):
            if rate is not None and not 0.0 <= rate <= 1.0:
                raise ValueError(f"{name} must be within [0, 1]")
        self._lock = threading.RLock()
        self.settlement: SettlementProvider = settlement_provider or FiatAndApiCreditLedger()
        self.canary_rate = canary_rate
        self.audit_rate = canary_rate if audit_rate is None else audit_rate
        self.audit_rewarded_steps = audit_rewarded_steps
        self.audit_confirm_runs = max(1, int(audit_confirm_runs))
        self.min_stake_units = min_stake_units
        self.ballast_ratio = max(0.0, ballast_ratio)
        self.min_ballast_pages = max(1, int(min_ballast_pages))
        self.ping_rounds = max(1, min(int(ping_rounds), 65_536))
        self.ping_repeats = max(1, int(ping_repeats))
        self.ping_spot_checks = max(1, int(ping_spot_checks))
        self.max_lookup_us = max_lookup_us
        self.max_lease_interval_s = max_lease_interval_s
        self.quarantine_on_fraud = quarantine_on_fraud
        self.timeout_strike_limit = max(1, int(timeout_strike_limit))
        self.max_billable_dirty_pages = max(0, int(max_billable_dirty_pages))
        self.step_timeout_ms = step_timeout_ms
        self.require_kernel_isolation = require_kernel_isolation
        self.state_path = state_path
        self._rng = secrets.SystemRandom()

        self._nodes: Dict[str, SRPProviderNode] = {}
        self._node_pubkeys: Dict[str, str] = {}
        self._node_profiles: Dict[str, str] = {}
        self._quarantined: Set[str] = set()
        self._quarantined_keys: Set[str] = set()
        self._timeout_strikes: Dict[str, int] = {}
        self.fraud_proofs: List[FraudProof] = []
        self._slash_amounts: Dict[int, float] = {}

        loaded = self._load_state() if state_path else {}
        secret_hex = loaded.get("master_secret_hex")
        self._master = master_secret or (bytes.fromhex(secret_hex) if secret_hex else secrets.token_bytes(32))
        seed_hex = loaded.get("coordinator_seed_hex")
        self.keypair = keypair or (NodeKeypair(bytes.fromhex(seed_hex)) if seed_hex else NodeKeypair.generate())

        self._auditors: Dict[str, _Auditor] = {}
        self.add_auditor(auditor_node or SRPProviderNode(node_id=self.AUDITOR_NODE_ID, ram_capacity_mb=auditor_ram_mb),
                         cache_size=audit_cache_size)

        self._snapshot_holders: Dict[str, List[str]] = {}
        self._manifests: Dict[str, SnapshotManifest] = {}
        self._ballast: Dict[Tuple[str, str], _BallastSpec] = {}
        self._lease_clock: Dict[Tuple[str, str], float] = {}

        self._branch_to_node: Dict[str, str] = {}
        self._branch_state_hashes: Dict[str, str] = {}
        self._branch_locks: Dict[str, threading.Lock] = {}
        self._branch_root: Dict[str, str] = {}
        self._branch_step_index: Dict[str, int] = {}
        self._branch_lineage: Dict[str, Optional[_Cell]] = {}
        self._closed_branches: Set[str] = set()
        self._lineage_pool: Dict[str, Deque[_Cell]] = collections.defaultdict(lambda: collections.deque(maxlen=64))

        self._canaries: List[CanaryTask] = []
        self._rr_counter = 0
        self.memory_pings_verified = 0
        self.audits_performed = 0
        self.audits_inconclusive = 0
        self.canaries_run = 0
        if state_path:
            self.save_state()

    # ============================================================ persistence
    def _load_state(self) -> Dict[str, Any]:
        if not self.state_path or not os.path.exists(self.state_path):
            return {}
        with open(self.state_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self._node_pubkeys.update(data.get("node_pubkeys", {}))
        self._node_profiles.update(data.get("node_profiles", {}))
        self._quarantined.update(data.get("quarantined", []))
        self._quarantined_keys.update(data.get("quarantined_keys", []))
        self._timeout_strikes.update(data.get("timeout_strikes", {}))
        for raw in data.get("fraud_proofs", []):
            rec = raw.pop("receipt", None)
            fp = FraudProof(**raw)
            fp.receipt = ExecutionReceipt(**rec) if rec else None
            self.fraud_proofs.append(fp)
        self._slash_amounts = {int(k): v for k, v in data.get("slash_amounts", {}).items()}
        return data

    def save_state(self) -> None:
        """Persist identities, quarantine, strikes, fraud evidence and secrets (atomic write)."""
        if not self.state_path:
            return
        with self._lock:
            data = {
                "version": PROTOCOL_VERSION,
                "node_pubkeys": dict(self._node_pubkeys),
                "node_profiles": dict(self._node_profiles),
                "quarantined": sorted(self._quarantined),
                "quarantined_keys": sorted(self._quarantined_keys),
                "timeout_strikes": dict(self._timeout_strikes),
                "fraud_proofs": [asdict(fp) for fp in self.fraud_proofs],
                "slash_amounts": {str(k): v for k, v in self._slash_amounts.items()},
                # Secrets: protect this file (or supply master_secret / keypair from a KMS)
                "master_secret_hex": self._master.hex(),
                "coordinator_seed_hex": self.keypair._seed.hex(),
            }
        tmp = f"{self.state_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, sort_keys=True)
        os.replace(tmp, self.state_path)

    # ================================================================ nodes
    def add_auditor(self, node: SRPProviderNode, cache_size: int = 256) -> None:
        """Register a trusted auditor; one per runtime profile."""
        auditor = _Auditor(node, cache_size, self.step_timeout_ms)
        with self._lock:
            self._auditors[auditor.profile] = auditor

    def register_node(self, node: SRPProviderNode) -> None:
        """
        NODE_REGISTER with proof-of-possession. Refuses: bad proofs, a node id bound
        to another key, quarantined ids or keys, unsupported protocol versions,
        runtime profiles no auditor can replay, insufficient stake and (when
        required) hosts without kernel-level sandbox isolation.
        """
        caps = node.capabilities()
        if caps.node_id != node.node_id or not caps.public_key_hex:
            raise PermissionError("Node capabilities do not match the registering node")
        if caps.node_id == self.AUDITOR_NODE_ID:
            raise PermissionError("Reserved node id")
        if caps.protocol_version != PROTOCOL_VERSION:
            raise PermissionError(f"Unsupported protocol version {caps.protocol_version!r}")
        nonce = secrets.token_hex(16)
        proof = node.prove_key_possession(nonce)
        if not verify_signature(
            caps.public_key_hex, registration_message(caps.node_id, caps.public_key_hex, nonce), proof
        ):
            raise PermissionError(f"Node '{caps.node_id}' failed key proof-of-possession")
        if self.require_kernel_isolation and not caps.sandbox_isolation.get("kernel_network_isolation"):
            raise PermissionError(f"Node '{caps.node_id}' lacks kernel-level sandbox isolation")

        with self._lock:
            if caps.node_id in self._quarantined or caps.public_key_hex in self._quarantined_keys:
                raise PermissionError(f"Node '{caps.node_id}' is quarantined for fraud")
            if caps.runtime_profile not in self._auditors:
                raise PermissionError(
                    f"No auditor for runtime profile {caps.runtime_profile!r}; its steps "
                    "could not be replayed deterministically"
                )
            known = self._node_pubkeys.get(caps.node_id)
            if known is not None and known != caps.public_key_hex:
                raise PermissionError(f"Node id '{caps.node_id}' is already bound to a different public key")
            if self._stake_of(caps.node_id) < self.min_stake_units:
                raise PermissionError(
                    f"Node '{caps.node_id}' stake is below the required "
                    f"{self.min_stake_units} {self.settlement.unit_symbol}"
                )
            self._nodes[caps.node_id] = node
            self._node_pubkeys[caps.node_id] = caps.public_key_hex
            self._node_profiles[caps.node_id] = caps.runtime_profile
        self.save_state()

    def _stake_of(self, node_id: str) -> float:
        stake_of = getattr(self.settlement, "stake_of", None)
        return stake_of(node_id) if stake_of else 0.0

    def is_quarantined(self, node_id: str) -> bool:
        with self._lock:
            return node_id in self._quarantined

    def _routable(self, node_id: str) -> bool:
        return (
            node_id in self._nodes
            and node_id not in self._quarantined
            and (self.min_stake_units <= 0 or self._stake_of(node_id) >= self.min_stake_units)
        )

    def _quarantine(self, node_id: str) -> None:
        with self._lock:
            self._quarantined.add(node_id)
            key = self._node_pubkeys.get(node_id)
            if key:
                self._quarantined_keys.add(key)
            for k in [k for k in self._lease_clock if k[0] == node_id]:
                self._lease_clock.pop(k, None)
        self.save_state()

    # ============================================================ snapshots
    def _ballast_spec(self, node_id: str, manifest: SnapshotManifest) -> _BallastSpec:
        key = (node_id, manifest.snapshot_id)
        spec = self._ballast.get(key)
        if spec is None:
            pub = self._node_pubkeys.get(node_id, "")
            seed = hmac.new(self._master, f"SRP_BALLAST_SEED_V2|{node_id}|{pub}|{manifest.snapshot_id}".encode(),
                            hashlib.sha256).digest()
            distinct = len(set(manifest.canonical_pages()[0]))
            count = max(self.min_ballast_pages, int(math.ceil(self.ballast_ratio * distinct)))
            spec = _BallastSpec(seed=seed, count=count)
            self._ballast[key] = spec
        return spec

    def broadcast_snapshot(
        self, manifest: SnapshotManifest, target_node_ids: Optional[List[str]] = None
    ) -> List[str]:
        """Pin a base snapshot plus node-unique sequential ballast on selected (or all routable) nodes."""
        expected_root = manifest.content_merkle_root
        with self._lock:
            existing = self._manifests.get(manifest.snapshot_id)
            if existing is not None and existing.content_merkle_root != expected_root:
                raise ValueError(f"Snapshot id '{manifest.snapshot_id}' already registered with different content")
            if target_node_ids is None:
                node_ids = [nid for nid in self._nodes if self._routable(nid)]
            else:
                node_ids = list(target_node_ids)
            if not node_ids:
                raise RuntimeError("No routable SRPProviderNodes to pin on")
            for nid in node_ids:
                if nid not in self._nodes:
                    raise KeyError(f"Unknown target node '{nid}'")
                if not self._routable(nid):
                    raise PermissionError(f"Node '{nid}' is quarantined or under-staked")
                caps = self._nodes[nid].capabilities()
                if manifest.suite not in caps.supported_suites:
                    raise ValueError(f"Node '{nid}' does not support verifier suite '{manifest.suite}'")
                if manifest.runtime not in caps.supported_runtimes:
                    raise ValueError(f"Node '{nid}' does not support runtime '{manifest.runtime}'")
            self._manifests[manifest.snapshot_id] = manifest
            nodes = {nid: self._nodes[nid] for nid in node_ids}
            specs = {nid: self._ballast_spec(nid, manifest) for nid in node_ids}

        pinned: List[str] = []
        for nid, node in nodes.items():  # node calls outside the coordinator lock
            snap = node.pin_snapshot(manifest)
            if snap.state_hash != expected_root:
                raise ValueError(f"Node '{nid}' pinned snapshot with a wrong state hash")
            spec = specs[nid]
            if node.ballast_page_count(manifest.snapshot_id) != spec.count:
                node.pin_ballast_seed(manifest.snapshot_id, spec.seed.hex(), spec.count)
            pinned.append(nid)

        with self._lock:
            holders = self._snapshot_holders.setdefault(manifest.snapshot_id, [])
            for nid in pinned:
                self._lease_clock.setdefault((nid, manifest.snapshot_id), time.time())
                if nid not in holders:
                    holders.append(nid)
            return list(holders)

    def evict_snapshot(self, snapshot_id: str, evict_branches: bool = True) -> int:
        """SRP_EVICT: drop a snapshot from every holder; a refusal keeps that holder routable."""
        with self._lock:
            holders = list(self._snapshot_holders.get(snapshot_id, []))
            nodes = {nid: self._nodes.get(nid) for nid in holders}
        total, done, error = 0, [], None
        for nid, node in nodes.items():
            try:
                if node:
                    total += node.evict_snapshot(snapshot_id=snapshot_id, evict_branches=evict_branches)
                done.append(nid)
            except Exception as exc:  # keep going; report the first refusal
                error = error or exc
        with self._lock:
            remaining = [h for h in self._snapshot_holders.get(snapshot_id, []) if h not in done]
            for nid in done:
                self._ballast.pop((nid, snapshot_id), None)
                self._lease_clock.pop((nid, snapshot_id), None)
            self._drop_stale_branches_locked()
            if remaining:
                self._snapshot_holders[snapshot_id] = remaining
            else:
                self._snapshot_holders.pop(snapshot_id, None)
                self._manifests.pop(snapshot_id, None)
                self._lineage_pool.pop(snapshot_id, None)
        if not remaining:
            for auditor in list(self._auditors.values()):
                auditor.drop_root(snapshot_id)
        if error is not None:
            raise error
        return total

    # ========================================================== residency
    def _ping_once(self, node: SRPProviderNode, snapshot_id: str, rounds: int):
        challenge = MemoryPingChallenge(
            challenge_id=f"mping_{uuid.uuid4().hex}", snapshot_id=snapshot_id,
            nonce=secrets.token_hex(16), sample_page_count=rounds,
        )
        t0 = time.perf_counter()
        resp = node.handle_memory_ping(challenge)
        return challenge, resp, (time.perf_counter() - t0) * 1000.0

    def verify_node_ram_residency(
        self, node_id: str, snapshot_id: str, max_latency_ms: Optional[float] = None
    ) -> Tuple[bool, float]:
        """
        SRP-003 Layer 3. Runs `ping_repeats` chained challenges, each preceded by
        a zero-lookup RTT baseline. Passes when every chain verifies and the median
        per-lookup latency (baseline subtracted) is within `max_lookup_us`;
        `max_latency_ms`, if given, bounds the baseline RTT itself. On success the
        node is paid the lease for its *ballast* (the only bytes that prove
        node-unique residency) over the interval since the previous challenge.
        Returns (passed, median challenge ms).
        """
        with self._lock:
            if node_id not in self._nodes:
                raise KeyError(f"Unknown node_id '{node_id}'")
            if snapshot_id not in self._manifests:
                raise KeyError(f"Unknown snapshot_id '{snapshot_id}'")
            if node_id in self._quarantined:
                return False, 0.0
            node = self._nodes[node_id]
            manifest = self._manifests[snapshot_id]
            spec = self._ballast_spec(node_id, manifest)

        ordered, page_map, _ = manifest.canonical_pages()
        page_hash = {i: hashlib.sha256(page_map[h]).hexdigest() for i, h in enumerate(ordered)}
        if spec.checkpoints is None:
            spec.checkpoints = BallastCheckpoints(spec.seed, spec.count)
        valid, per_lookup, mains, baselines = True, [], [], []
        try:
            for _ in range(self.ping_repeats):
                _, base_resp, base_ms = self._ping_once(node, snapshot_id, 0)
                ch, resp, main_ms = self._ping_once(node, snapshot_id, self.ping_rounds)
                ok = (
                    resp.challenge_id == ch.challenge_id and resp.node_id == node_id
                    and resp.snapshot_id == snapshot_id and base_resp.node_id == node_id
                )
                if ok:
                    ok, _reason = verify_chain(
                        ch.nonce, ch.sample_page_count, len(ordered), spec.count,
                        resp.sampled_page_indices, resp.page_hashes, resp.combined_digest,
                        lambda i: page_hash[i], spec.checkpoints.page, self.ping_spot_checks,
                    )
                valid = valid and ok
                baselines.append(base_ms)
                mains.append(main_ms)
                per_lookup.append(max(0.0, main_ms - base_ms) * 1000.0 / ch.sample_page_count)
        except Exception:
            valid = False
        if valid:
            valid = statistics.median(per_lookup) <= self.max_lookup_us
        if valid and max_latency_ms is not None:
            valid = statistics.median(baselines) <= max_latency_ms

        now = time.time()
        with self._lock:
            key = (node_id, snapshot_id)
            last = self._lease_clock.get(key, now)
            self._lease_clock[key] = now
            if valid:
                self.memory_pings_verified += 1
        if valid:
            interval = max(0.0, min(now - last, self.max_lease_interval_s))
            if interval > 0:
                self.settlement.record_ram_lease(
                    node_id=node_id, pinned_bytes=spec.count * PAGE_SIZE, duration_seconds=interval
                )
        return bool(valid), (statistics.median(mains) if mains else 0.0)

    # ============================================================== forks
    def fork(
        self,
        source_id: str,
        count: int = 1,
        preferred_node_id: Optional[str] = None,
        ttl_seconds: Optional[float] = None,
    ) -> Tuple[List[str], float]:
        """Route `SRP_FORK`; branch ids are minted here and checked in the node's reply."""
        if not 0 <= int(count) <= 4096:
            raise ValueError("count must be within [0, 4096]")
        with self._lock:
            if source_id in self._branch_to_node:
                nid = self._branch_to_node[source_id]
                if preferred_node_id and preferred_node_id != nid:
                    raise KeyError(f"Branch '{source_id}' resides on node '{nid}', not '{preferred_node_id}'")
                if not self._routable(nid):
                    raise PermissionError(f"Node '{nid}' is quarantined or under-staked")
                if source_id in self._closed_branches:
                    raise KeyError(f"Branch '{source_id}' is closed")
                parent_lock: Optional[threading.Lock] = self._branch_locks.setdefault(source_id, threading.Lock())
            else:
                all_holders = self._snapshot_holders.get(source_id, [])
                holders = [h for h in all_holders if self._routable(h)]
                if not holders:
                    if all_holders:
                        raise PermissionError(f"Every node holding '{source_id}' is quarantined or under-staked")
                    raise KeyError(f"No registered node holds snapshot or branch '{source_id}'")
                if preferred_node_id:
                    if preferred_node_id not in self._nodes:
                        raise KeyError(f"Unknown preferred_node_id '{preferred_node_id}'")
                    if preferred_node_id not in holders:
                        raise KeyError(f"Preferred node '{preferred_node_id}' does not hold snapshot '{source_id}'")
                    nid = preferred_node_id
                else:
                    nid = holders[self._rr_counter % len(holders)]
                    self._rr_counter += 1
                parent_lock = None
            node = self._nodes[nid]

        if parent_lock is not None:
            with parent_lock:
                return self._fork_from(node, nid, source_id, int(count), ttl_seconds, is_branch=True)
        return self._fork_from(node, nid, source_id, int(count), ttl_seconds, is_branch=False)

    def _fork_from(
        self, node: SRPProviderNode, nid: str, source_id: str, count: int,
        ttl_seconds: Optional[float], is_branch: bool,
    ) -> Tuple[List[str], float]:
        with self._lock:
            if is_branch:
                if source_id not in self._branch_to_node:
                    raise KeyError(f"Branch '{source_id}' was evicted")
                expected_hash = self._branch_state_hashes[source_id]
                root = self._branch_root[source_id]
                lineage = self._branch_lineage.get(source_id)
            else:
                expected_hash = self._manifests[source_id].content_merkle_root
                root, lineage = source_id, None
            minted = [f"br_{uuid.uuid4().hex}" for _ in range(count)]

        branches, elapsed_ms = node.fork(
            source_id=source_id, count=count, ttl_seconds=ttl_seconds, branch_ids=minted
        )
        got = [b.branch_id for b in branches]
        fault = None
        if got != minted:
            fault = "Fork reply branch ids differ from the coordinator-minted ids"
        elif any(b.state_hash != expected_hash or b.root_snapshot_id != root for b in branches):
            fault = "Forked branch state does not match its source"
        if fault:
            for bid in set(got) | set(minted):
                try:
                    node.evict_branch(bid)
                except Exception:
                    pass
            self._record_fault(nid, fault)
            raise PermissionError(f"Node {nid}: {fault}")

        with self._lock:
            for bid in minted:
                self._branch_to_node[bid] = nid
                self._branch_state_hashes[bid] = expected_hash
                self._branch_locks[bid] = threading.Lock()
                self._branch_root[bid] = root
                self._branch_step_index[bid] = 0
                self._branch_lineage[bid] = lineage
        return minted, elapsed_ms

    # ============================================================== steps
    def step(self, branch_id: str, action: ActionPayload, timeout_ms: Optional[int] = None) -> StepResult:
        """
        Route `SRP_STEP`, verify the signed receipt, (blindly) audit, and credit the
        node. Raises PermissionError after quarantine (and slashing, for provable
        fraud) on any verification failure.
        """
        with self._lock:
            if branch_id not in self._branch_to_node:
                raise KeyError(f"Unknown branch_id '{branch_id}'")
            branch_lock = self._branch_locks.setdefault(branch_id, threading.Lock())
        with branch_lock:
            return self._dispatch(branch_id, action, timeout_ms, allow_audit=True)

    def _dispatch(
        self, branch_id: str, action: ActionPayload, timeout_ms: Optional[int], allow_audit: bool,
        force_audit: bool = False,
    ) -> StepResult:
        with self._lock:
            if branch_id not in self._branch_to_node:
                raise KeyError(f"Unknown branch_id '{branch_id}'")
            if branch_id in self._closed_branches:
                raise KeyError(f"Branch '{branch_id}' is closed (previous step hit the wall-clock backstop)")
            nid = self._branch_to_node[branch_id]
            if not self._routable(nid):
                raise PermissionError(f"Node '{nid}' is quarantined or under-staked")
            node = self._nodes[nid]
            pubkey = self._node_pubkeys[nid]
            profile = self._node_profiles.get(nid, "")
            expected_parent = self._branch_state_hashes[branch_id]
            expected_index = self._branch_step_index[branch_id] + 1
            root = self._branch_root[branch_id]
            lineage = self._branch_lineage.get(branch_id)
            manifest = self._manifests.get(root)

        frozen = _freeze_action(action)
        action = _thaw(frozen)
        timeout = int(timeout_ms or self.step_timeout_ms)
        request_id = f"req_{uuid.uuid4().hex}"
        try:
            result = node.step(branch_id=branch_id, action=action, request_id=request_id, timeout_ms=timeout)
        except KeyError:
            with self._lock:
                self._forget_branch_locked(branch_id)
            raise
        except Exception:
            # Unknown whether the node advanced: the branch can no longer be trusted.
            self._abandon_branch(node, branch_id)
            raise

        rec = result.receipt
        fault = self._layer1(rec, result, nid, pubkey, branch_id, request_id, root,
                             expected_index, expected_parent, action, timeout)
        if fault is not None:
            self._abandon_branch(node, branch_id)
            self._record_fault(nid, fault, result)
            raise PermissionError(f"Node {nid} failed verification: {fault}")

        parent_digest = lineage.digest if lineage else _root_digest(root, manifest.content_merkle_root if manifest else "")
        digest = _cell_digest(parent_digest, frozen, timeout)
        timed_out = _timed_out(result)
        verdict: Dict[str, Any] = {"status": "skipped"}
        must_audit = force_audit or timed_out or (
            self.audit_rewarded_steps and (result.reward != 0.0 or result.terminated)
        )
        if allow_audit and manifest is not None and (
            must_audit or (self.audit_rate > 0 and self._rng.random() < self.audit_rate)
        ):
            try:
                verdict = self._audit(profile, manifest, lineage, action, timeout, digest, result)
            except Exception:
                # The coordinator's own failure must never desync or frame the node.
                verdict = {"status": "inconclusive"}
                with self._lock:
                    self.audits_inconclusive += 1

        if verdict["status"] == "fraud":
            self._abandon_branch(node, branch_id)
            fp = self._record_fraud(nid, verdict["reason"], verdict["receipt"], verdict["kind"],
                                    manifest, verdict["lineage"], profile, verdict.get("truth"))
            raise PermissionError(f"Node {nid} failed verification: {verdict['reason']} ({fp.kind})")
        if verdict["status"] == "timeout_strike":
            with self._lock:
                strikes = self._timeout_strikes.get(nid, 0) + 1
                self._timeout_strikes[nid] = strikes
            if strikes >= self.timeout_strike_limit:
                self._record_fault(nid, f"{strikes} contradicted wall-clock timeout claims", result)

        cell = _Cell(frozen, timeout, rec, lineage, digest, (lineage.depth + 1) if lineage else 1)
        with self._lock:
            if branch_id in self._branch_to_node:
                self._branch_state_hashes[branch_id] = rec.next_state_hash
                self._branch_step_index[branch_id] = expected_index
                self._branch_lineage[branch_id] = cell
                if timed_out:
                    self._closed_branches.add(branch_id)
            self._lineage_pool[root].append(cell)

        if not timed_out:  # an indeterminate step earns nothing
            self.settlement.record_verified_step(
                node_id=nid,
                compute_ms=result.metrics.exec_time_ms,
                dirty_pages=min(rec.step_dirty_pages, self.max_billable_dirty_pages),
            )
        self._maybe_schedule_canary(nid)
        return result

    @staticmethod
    def _layer1(rec, result, nid, pubkey, branch_id, request_id, root, expected_index,
                expected_parent, action, timeout) -> Optional[str]:
        if not rec.verify_signature(pubkey):
            return "Invalid Ed25519 receipt signature"
        if rec.node_id != nid or rec.branch_id != branch_id or result.branch_id != branch_id:
            return "Receipt node_id or branch_id mismatch"
        if rec.request_id != request_id or result.request_id != request_id:
            return "Receipt request_id does not match the dispatched request (replay?)"
        if rec.root_snapshot_id != root:
            return "Receipt root_snapshot_id mismatch"
        if rec.step_index != expected_index:
            return f"Receipt step_index {rec.step_index} != expected {expected_index}"
        if rec.parent_state_hash != expected_parent:
            return f"Broken state hash chain: expected parent {expected_parent[:12]}, got {rec.parent_state_hash[:12]}"
        if rec.action_hash != action.action_hash:
            return "Receipt action_hash does not match dispatched ActionPayload"
        if int(rec.timeout_ms) != timeout:
            return "Receipt timeout_ms does not match the dispatched timeout"
        if not isinstance(result.reward, float) or not math.isfinite(result.reward):
            return "Non-finite reward"
        if rec.reward != result.reward or rec.terminated != result.terminated or rec.truncated != result.truncated:
            return "Receipt reward/terminated/truncated do not match StepResult"
        if rec.stdout_hash != sha256_hex(result.observation.stdout):
            return "Receipt stdout_hash does not match observation.stdout"
        try:
            obs_hash = result.observation.canonical_hash(result.truncated)
        except (TypeError, ValueError):
            return "Observation is not canonically serialisable"
        if rec.observation_hash != obs_hash:
            return "Receipt observation_hash does not match the returned observation"
        if rec.step_dirty_pages != result.metrics.step_dirty_pages:
            return "Receipt step_dirty_pages does not match metrics"
        return None

    # ============================================================ auditing
    def _audit(self, profile, manifest, lineage, action, timeout, digest, result) -> Dict[str, Any]:
        auditor = self._auditors.get(profile)
        if auditor is None:
            return {"status": "inconclusive"}
        with self._lock:
            self.audits_performed += 1
        history = _cells(lineage)
        rec = result.receipt
        out = auditor.run(manifest, history, action, timeout, digest)

        if out["status"] == "indeterminate":
            with self._lock:
                self.audits_inconclusive += 1
            return {"status": "inconclusive"}

        if out["status"] == "prefix_mismatch":
            bad: _Cell = out["cell"]
            if not self._confirmed(auditor, manifest, _cells(bad.parent), _thaw(bad.action_json),
                                   bad.timeout_ms, bad.receipt):
                with self._lock:
                    self.audits_inconclusive += 1
                return {"status": "inconclusive"}
            return {
                "status": "fraud", "kind": FRAUD_KIND_REPLAY, "receipt": bad.receipt,
                "reason": f"Replay audit: committed step {bad.depth} diverges from trusted replay",
                "lineage": _cells(bad), "truth": out["truth"],
            }

        truth: StepResult = out["truth"]
        if _timed_out(result) or _timed_out(truth):
            backstop = 2 * timeout + 1000
            if _timed_out(result) and not _timed_out(truth) and out["elapsed_ms"] < 0.25 * backstop:
                return {"status": "timeout_strike"}
            with self._lock:
                self.audits_inconclusive += 1
            return {"status": "inconclusive"}
        if out["before"] == rec.parent_state_hash and _outcome(truth.receipt)[1:] == _outcome(rec)[1:]:
            return {"status": "ok"}
        if not self._confirmed(auditor, manifest, history, action, timeout, rec):
            with self._lock:
                self.audits_inconclusive += 1
            return {"status": "inconclusive"}
        here = _Cell(_freeze_action(action), timeout, rec, lineage, digest, (lineage.depth + 1) if lineage else 1)
        return {
            "status": "fraud", "kind": FRAUD_KIND_REPLAY, "receipt": rec,
            "reason": "Replay audit: result differs from trusted replay",
            "lineage": _cells(here), "truth": truth,
        }

    def _confirmed(self, auditor, manifest, history, action, timeout, claimed: ExecutionReceipt) -> bool:
        """A mismatch is fraud only if every repeated trusted run agrees and contradicts the node."""
        outcomes = set()
        for _ in range(self.audit_confirm_runs):
            out = auditor.run(manifest, history, action, timeout, None)
            if out["status"] != "ok" or _timed_out(out["truth"]):
                return False
            outcomes.add(_outcome(out["truth"].receipt)[1:])
        return len(outcomes) == 1 and _outcome(claimed)[1:] not in outcomes

    # ============================================================= canaries
    def register_canary(
        self, snapshot_id: str, action: ActionPayload,
        expected_reward: Optional[float] = None, expected_state_hash: Optional[str] = None,
    ) -> None:
        """Add a canary task; ground truth defaults to a trusted auditor replay."""
        with self._lock:
            if snapshot_id not in self._manifests:
                raise KeyError(f"Unknown snapshot_id '{snapshot_id}'")
            self._canaries.append(CanaryTask(snapshot_id, action, expected_reward, expected_state_hash))

    def _maybe_schedule_canary(self, node_id: str) -> None:
        if not self._canaries or self.canary_rate <= 0 or self._rng.random() >= self.canary_rate:
            return
        threading.Thread(target=self._safe_canary, args=(node_id,), daemon=True).start()

    def _safe_canary(self, node_id: str) -> None:
        try:
            self.run_canary_round([node_id])
        except Exception:
            pass

    def run_canary_round(self, node_ids: Optional[List[str]] = None) -> List[Tuple[str, bool]]:
        """Send one random canary to each (routable) node, in random order, at a random depth."""
        with self._lock:
            targets = list(node_ids) if node_ids is not None else [n for n in self._nodes if self._routable(n)]
            canaries = list(self._canaries)
            holders = {k: list(v) for k, v in self._snapshot_holders.items()}
            pools = {k: list(v) for k, v in self._lineage_pool.items()}
        self._rng.shuffle(targets)
        results: List[Tuple[str, bool]] = []
        for nid in targets:
            eligible = [c for c in canaries if nid in holders.get(c.snapshot_id, [])]
            if not eligible:
                continue
            task = self._rng.choice(eligible)
            prefix: List[_Cell] = []
            pool = pools.get(task.snapshot_id) or []
            if pool and self._rng.random() < 0.75:
                full = _cells(self._rng.choice(pool))
                prefix = full[: self._rng.randint(0, len(full))]
            ok, _ = self.inject_canary_audit(
                nid, task.snapshot_id, task.action, task.expected_reward, task.expected_state_hash,
                prefix=[(_thaw(c.action_json), c.timeout_ms) for c in prefix],
            )
            results.append((nid, ok))
        return results

    def inject_canary_audit(
        self,
        node_id: str,
        snapshot_id: str,
        canary_action: ActionPayload,
        expected_reward: Optional[float] = None,
        expected_state_hash: Optional[str] = None,
        prefix: Optional[List[Tuple[ActionPayload, int]]] = None,
    ) -> Tuple[bool, Optional[FraudProof]]:
        """
        SRP-003 Layer 2 canary through the ordinary fork/step path (audits stay
        eligible), optionally after a prefix of real actions so it can sit at any
        depth. Ground truth comes from the trusted auditor unless supplied.
        """
        with self._lock:
            if node_id not in self._nodes:
                raise KeyError(f"Unknown node_id '{node_id}'")
            manifest = self._manifests.get(snapshot_id)
            profile = self._node_profiles.get(node_id, "")
            self.canaries_run += 1
        if manifest is None:
            raise KeyError(f"Unknown snapshot_id '{snapshot_id}'")
        prefix = list(prefix or [])

        ids, _ = self.fork(snapshot_id, count=1, preferred_node_id=node_id)
        bid = ids[0]
        try:
            with self._lock:
                lock = self._branch_locks.get(bid)
            if lock is None:
                raise KeyError(f"Canary branch '{bid}' disappeared")
            with lock:
                try:
                    for act, t in prefix:
                        self._dispatch(bid, act, t, allow_audit=True)
                    res = self._dispatch(bid, canary_action, None, allow_audit=True)
                except PermissionError:
                    with self._lock:
                        fp = next((p for p in reversed(self.fraud_proofs) if p.node_id == node_id), None)
                    return False, fp
                with self._lock:
                    lineage = self._branch_lineage.get(bid)
            if expected_reward is None or expected_state_hash is None:
                auditor = self._auditors.get(profile)
                if auditor is None:
                    return True, None
                out = auditor.run(manifest, _cells(lineage.parent if lineage else None), canary_action,
                                  self.step_timeout_ms, None)
                if out["status"] != "ok" or _timed_out(out["truth"]):
                    return True, None
                expected_reward = out["truth"].reward if expected_reward is None else expected_reward
                expected_state_hash = (
                    out["truth"].receipt.next_state_hash if expected_state_hash is None else expected_state_hash
                )
            rec = res.receipt
            reason = None
            if not abs(res.reward - expected_reward) <= 1e-9:
                reason = f"Canary reward mismatch: expected {expected_reward}, got {res.reward}"
            elif rec.next_state_hash != expected_state_hash:
                reason = f"Canary state hash mismatch: expected {expected_state_hash[:12]}, got {rec.next_state_hash[:12]}"
            if reason is not None:
                fp = self._record_fraud(node_id, reason, rec, FRAUD_KIND_CANARY, manifest,
                                        _cells(lineage), profile, None,
                                        expected_reward=expected_reward, expected_state_hash=expected_state_hash)
                return False, fp
            return True, None
        finally:
            self.evict_branch(bid)

    # ================================================================ fraud
    def _record_fault(self, node_id: str, reason: str, result: Optional[StepResult] = None) -> FraudProof:
        """Non-slashable protocol fault: recorded and quarantined."""
        with self._lock:
            pubkey = self._node_pubkeys.get(node_id, "")
        fp = FraudProof(
            node_id=node_id, request_id=result.request_id if result else "", reason=reason,
            expected_reward=0.0, actual_reward=result.reward if result else 0.0,
            timestamp=time.time(), receipt=result.receipt if result else None,
            node_public_key_hex=pubkey, kind="protocol_fault",
        )
        with self._lock:
            self.fraud_proofs.append(fp)
        if self.quarantine_on_fraud:
            self._quarantine(node_id)
        else:
            self.save_state()
        return fp

    def _record_fraud(
        self, node_id: str, reason: str, receipt: ExecutionReceipt, kind: str,
        manifest: SnapshotManifest, lineage_cells: List[_Cell], profile: str,
        truth: Optional[StepResult], expected_reward: Optional[float] = None,
        expected_state_hash: Optional[str] = None,
    ) -> FraudProof:
        with self._lock:
            pubkey = self._node_pubkeys.get(node_id, "")
        lineage = [
            {"command": _thaw(c.action_json).command, "payload": _thaw(c.action_json).payload,
             "timeout_ms": c.timeout_ms}
            for c in lineage_cells
        ]
        fp = FraudProof(
            node_id=node_id, request_id=receipt.request_id, reason=reason,
            expected_reward=(truth.reward if truth else (expected_reward or 0.0)),
            actual_reward=receipt.reward,
            expected_state_hash=(truth.receipt.next_state_hash if truth else expected_state_hash),
            actual_state_hash=receipt.next_state_hash, timestamp=time.time(), receipt=receipt,
            node_public_key_hex=pubkey, kind=kind, root_snapshot_id=manifest.snapshot_id,
            root_content_hash=manifest.content_merkle_root, lineage=lineage,
            runtime_profile=profile,
            trusted_observation_hash=(truth.receipt.observation_hash if truth else ""),
        )
        with self._lock:
            self.fraud_proofs.append(fp)
            index = len(self.fraud_proofs) - 1
        if fp.slashable:
            rec = self.settlement.record_canary_failure(node_id, fp)
            with self._lock:
                self._slash_amounts[index] = -float(getattr(rec, "delta_units", 0.0))
        if self.quarantine_on_fraud:
            self._quarantine(node_id)
        else:
            self.save_state()
        return fp

    def appeal_fraud(self, proof_index: int) -> bool:
        """
        Re-check a slashable FraudProof by independent deterministic replay. If the
        fraud is NOT confirmed, the node is reinstated and its slash refunded.
        Returns True when the appeal succeeds.
        """
        with self._lock:
            fp = self.fraud_proofs[proof_index]
            manifest = self._manifests.get(fp.root_snapshot_id)
        if fp.kind not in (FRAUD_KIND_REPLAY, FRAUD_KIND_CANARY) or manifest is None:
            return False
        if verify_fraud_proof_by_replay(fp, manifest, runs=self.audit_confirm_runs + 1):
            return False
        amount = self._slash_amounts.pop(proof_index, 0.0)
        refund = getattr(self.settlement, "reverse_slash", None)
        if amount and refund:
            refund(fp.node_id, amount, f"appeal of proof #{proof_index}")
        with self._lock:
            self._quarantined.discard(fp.node_id)
            if fp.node_public_key_hex:
                self._quarantined_keys.discard(fp.node_public_key_hex)
            fp.reason = f"[OVERTURNED ON APPEAL] {fp.reason}"
            fp.kind = "overturned"
        self.save_state()
        return True

    # ============================================================ lifecycle
    def _abandon_branch(self, node: SRPProviderNode, branch_id: str) -> None:
        with self._lock:
            self._forget_branch_locked(branch_id)
        try:
            node.evict_branch(branch_id)
        except Exception:
            pass

    def _forget_branch_locked(self, branch_id: str) -> Optional[str]:
        nid = self._branch_to_node.pop(branch_id, None)
        for d in (self._branch_state_hashes, self._branch_locks, self._branch_root,
                  self._branch_step_index, self._branch_lineage):
            d.pop(branch_id, None)
        self._closed_branches.discard(branch_id)
        return nid

    def _drop_stale_branches_locked(self) -> None:
        stale = [bid for bid, nid in self._branch_to_node.items()
                 if nid in self._nodes and not self._nodes[nid].has_branch(bid)]
        for bid in stale:
            self._forget_branch_locked(bid)

    def evict_branch(self, branch_id: str) -> int:
        with self._lock:
            nid = self._forget_branch_locked(branch_id)
            if not nid or nid not in self._nodes:
                return 0
            node = self._nodes[nid]
        return node.evict_branch(branch_id)

    def reap_expired_branches(self) -> int:
        """Enforce SRP_FORK `ttl_seconds` across nodes; returns branches reaped."""
        with self._lock:
            nodes = list(self._nodes.values())
        reaped = sum(len(n.reap_expired()) for n in nodes)
        with self._lock:
            self._drop_stale_branches_locked()
        return reaped

    def cluster_telemetry(self) -> Dict[str, object]:
        with self._lock:
            nodes_snapshot = dict(self._nodes)
            quarantined = sorted(self._quarantined)
            fraud = [fp for fp in self.fraud_proofs if fp.kind != "overturned"]
        node_stats = {nid: n.telemetry() for nid, n in nodes_snapshot.items()}
        total_used = sum(int(s["base_ram_bytes"]) + int(s["dirty_ram_bytes"]) for s in node_stats.values())
        total_logical = sum(int(s["logical_unshared_bytes"]) for s in node_stats.values())
        savings = (1.0 - total_used / total_logical) * 100.0 if total_logical and total_logical >= total_used else 0.0
        return {
            "registered_nodes": len(nodes_snapshot),
            "quarantined_nodes": quarantined,
            "cluster_capacity_bytes": sum(int(s["capacity_bytes"]) for s in node_stats.values()),
            "cluster_used_ram_bytes": total_used,
            "cluster_ballast_bytes": sum(int(s["ballast_ram_bytes"]) for s in node_stats.values()),
            "cluster_logical_bytes": total_logical,
            "cluster_cow_savings_percent": round(savings, 2),
            "memory_pings_verified": self.memory_pings_verified,
            "replay_audits_performed": self.audits_performed,
            "replay_audits_inconclusive": self.audits_inconclusive,
            "canaries_run": self.canaries_run,
            "fraud_proofs_triggered": len([f for f in fraud if f.slashable]),
            "protocol_faults": len([f for f in fraud if f.kind == "protocol_fault"]),
            "nodes": node_stats,
            "settlement": self.settlement.summary(),
        }
