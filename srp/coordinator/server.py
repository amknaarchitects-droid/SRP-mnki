"""
SRP Coordinator & Verification Mesh
===================================
Orchestrates snapshot pinning, Snapshot-Aware Routing, GRPO/MCTS multi-branch
forking, Proof-of-Honest-RAM (`MemoryPingChallenge`), Blind Canary Verification,
and Pluggable Settlement accounting.
"""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from typing import Dict, List, Optional, Tuple

from srp.node.daemon import SRPProviderNode
from srp.protocol.messages import (
    ActionPayload,
    FraudProof,
    MemoryPingChallenge,
    SnapshotManifest,
    StepResult,
)
from srp.settlement.base import FiatAndApiCreditLedger, SettlementProvider


class SRPCoordinator:
    """
    Coordinates a pool of SRPProviderNodes, routes RL rollout steps to nodes
    already holding the required snapshot/branch in volatile RAM, verifies
    cryptographic receipts & blind canaries, and settles contributor rewards.
    """

    def __init__(
        self,
        settlement_provider: Optional[SettlementProvider] = None,
        canary_rate: float = 0.05,
    ) -> None:
        self.settlement: SettlementProvider = (
            settlement_provider or FiatAndApiCreditLedger()
        )
        self.canary_rate = canary_rate
        self._nodes: Dict[str, SRPProviderNode] = {}
        self._snapshot_holders: Dict[str, List[str]] = {}
        self._branch_to_node: Dict[str, str] = {}
        self._manifests: Dict[str, SnapshotManifest] = {}
        self._rr_counter: int = 0
        self.fraud_proofs: List[FraudProof] = []
        self.memory_pings_verified: int = 0

    def register_node(self, node: SRPProviderNode) -> None:
        """Register an SRPProviderNode with the Coordinator mesh."""
        self._nodes[node.node_id] = node

    def broadcast_snapshot(
        self, manifest: SnapshotManifest, target_node_ids: Optional[List[str]] = None
    ) -> List[str]:
        """
        Pin a base snapshot into the volatile RAM Arena of selected (or all) nodes.
        """
        self._manifests[manifest.snapshot_id] = manifest
        node_ids = target_node_ids or list(self._nodes.keys())
        if not node_ids:
            raise RuntimeError("No SRPProviderNodes registered with Coordinator")

        holders = self._snapshot_holders.setdefault(manifest.snapshot_id, [])
        for nid in node_ids:
            node = self._nodes[nid]
            snap = node.pin_snapshot(manifest)
            if nid not in holders:
                holders.append(nid)
            # Credit initial RAM lease heartbeat (e.g., 60s baseline pin window)
            self.settlement.record_ram_lease(
                node_id=nid, pinned_bytes=snap.raw_bytes, duration_seconds=60.0
            )
        return holders

    def verify_node_ram_residency(
        self, node_id: str, snapshot_id: str, max_latency_ms: float = 10.0
    ) -> Tuple[bool, float]:
        """
        SRP-003 Layer 3: Issue a random-page MemoryPingChallenge to verify that
        the node holds the snapshot in fast physical DRAM (not slow disk swap)
        and returns the exact expected cryptographic page digest.
        """
        node = self._nodes[node_id]
        manifest = self._manifests[snapshot_id]
        nonce = secrets.token_hex(16)
        challenge = MemoryPingChallenge(
            challenge_id=f"mping_{uuid.uuid4().hex[:8]}",
            snapshot_id=snapshot_id,
            nonce=nonce,
            sample_page_count=16,
            max_latency_ms=max_latency_ms,
        )
        resp = node.handle_memory_ping(challenge)

        # Independently verify the expected digest from the canonical page table
        snap = node.arena._snapshots[snapshot_id]
        hasher = hashlib.sha256(nonce.encode("utf-8"))
        total_pages = len(snap.ordered_page_hashes)
        for i in range(challenge.sample_page_count):
            seed_bytes = hashlib.sha256(f"{nonce}:{i}".encode("utf-8")).digest()
            idx = int.from_bytes(seed_bytes[:4], "big") % total_pages
            phash = snap.ordered_page_hashes[idx]
            hasher.update(node.arena._base_pages[phash])

        expected_digest = hasher.hexdigest()
        valid = (
            resp.combined_digest == expected_digest
            and resp.elapsed_ms <= max_latency_ms
            and snap.manifest.content_merkle_root == manifest.content_merkle_root
        )
        if valid:
            self.memory_pings_verified += 1
        return valid, resp.elapsed_ms

    def fork(
        self, source_id: str, count: int = 1, preferred_node_id: Optional[str] = None
    ) -> Tuple[List[str], float]:
        """
        Route an `SRP_FORK` request to a node holding `source_id` (either a base
        snapshot or an existing mid-rollout branch) and return the new `branch_ids`.
        """
        if source_id in self._branch_to_node:
            nid = self._branch_to_node[source_id]
        elif preferred_node_id and preferred_node_id in self._nodes:
            nid = preferred_node_id
        else:
            holders = self._snapshot_holders.get(source_id, [])
            if not holders:
                raise KeyError(f"No registered node holds snapshot or branch '{source_id}'")
            nid = holders[self._rr_counter % len(holders)]
            self._rr_counter += 1

        node = self._nodes[nid]
        branches, elapsed_ms = node.fork(source_id=source_id, count=count)
        branch_ids = []
        for b in branches:
            self._branch_to_node[b.branch_id] = nid
            branch_ids.append(b.branch_id)
        return branch_ids, elapsed_ms

    def step(self, branch_id: str, action: ActionPayload) -> StepResult:
        """
        Route an `SRP_STEP` to the node holding `branch_id`, verify the cryptographic
        ExecutionReceipt, and credit the node via the pluggable SettlementProvider.
        """
        if branch_id not in self._branch_to_node:
            raise KeyError(f"Unknown branch_id '{branch_id}'")
        nid = self._branch_to_node[branch_id]
        node = self._nodes[nid]

        result = node.step(branch_id=branch_id, action=action)

        # Verify cryptographic HMAC signature on the ExecutionReceipt
        if not result.receipt.verify_signature(node.secret_key):
            fp = FraudProof(
                node_id=nid,
                request_id=result.request_id,
                reason="Invalid cryptographic receipt signature",
                expected_reward=0.0,
                actual_reward=result.reward,
                timestamp=time.time(),
            )
            self.fraud_proofs.append(fp)
            self.settlement.record_canary_failure(nid, fp)
            raise PermissionError(f"Node {nid} failed receipt signature verification!")

        # Credit the contributor node for the verified step
        self.settlement.record_verified_step(
            node_id=nid,
            compute_ms=result.metrics.exec_time_ms,
            dirty_pages=result.metrics.dirty_pages,
        )
        return result

    def inject_canary_audit(
        self,
        node_id: str,
        snapshot_id: str,
        canary_action: ActionPayload,
        expected_reward: float,
    ) -> Tuple[bool, Optional[FraudProof]]:
        """
        SRP-003 Layer 2: Dispatch an indistinguishable canary rollout step to `node_id`
        and verify that its returned reward and state transition match ground truth.
        """
        node = self._nodes[node_id]
        branches, _ = node.fork(source_id=snapshot_id, count=1)
        canary_branch = branches[0]
        try:
            res = node.step(branch_id=canary_branch.branch_id, action=canary_action)
            if abs(res.reward - expected_reward) > 1e-4:
                fp = FraudProof(
                    node_id=node_id,
                    request_id=res.request_id,
                    reason=(
                        f"Canary reward mismatch: expected {expected_reward}, "
                        f"got {res.reward}"
                    ),
                    expected_reward=expected_reward,
                    actual_reward=res.reward,
                    timestamp=time.time(),
                )
                self.fraud_proofs.append(fp)
                self.settlement.record_canary_failure(node_id, fp)
                return False, fp
            return True, None
        finally:
            node.evict_branch(canary_branch.branch_id)

    def evict_branch(self, branch_id: str) -> int:
        nid = self._branch_to_node.pop(branch_id, None)
        if not nid:
            return 0
        return self._nodes[nid].evict_branch(branch_id)

    def cluster_telemetry(self) -> Dict[str, object]:
        node_stats = {nid: n.telemetry() for nid, n in self._nodes.items()}
        total_cap = sum(int(s["capacity_bytes"]) for s in node_stats.values())
        total_used = sum(int(s["used_ram_bytes"]) for s in node_stats.values())
        total_logical = sum(int(s["logical_unshared_bytes"]) for s in node_stats.values())
        cluster_savings = (
            (1.0 - (total_used / total_logical)) * 100.0
            if total_logical > 0 and total_logical >= total_used
            else 0.0
        )
        return {
            "registered_nodes": len(self._nodes),
            "cluster_capacity_bytes": total_cap,
            "cluster_used_ram_bytes": total_used,
            "cluster_logical_bytes": total_logical,
            "cluster_cow_savings_percent": round(cluster_savings, 2),
            "memory_pings_verified": self.memory_pings_verified,
            "fraud_proofs_triggered": len(self.fraud_proofs),
            "nodes": node_stats,
            "settlement": self.settlement.summary(),
        }
