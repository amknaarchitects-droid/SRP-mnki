"""
SRP Provider Node Daemon
========================
Manages a contributor's shared volatile RAM Arena, executes Copy-on-Write
forking (`SRP_FORK`) and sandboxed RL steps (`SRP_STEP`), signs Ed25519
execution receipts, and answers Proof-of-Honest-RAM challenges.

The node's private key never leaves this object: coordinators verify receipts
with the public key published in `NodeCapabilities`.
"""

from __future__ import annotations

import math
import threading
import time
import uuid
from typing import Dict, List, Optional, Tuple

from srp.node.ram_arena import PAGE_SIZE, CoWBranch, PinnedSnapshot, VolatileRAMArena
from srp.node.runtimes import RUNTIME_ENGINES
from srp.protocol.crypto import NodeKeypair, registration_message
from srp.protocol.residency import generate_ballast
from srp.envs.sandbox import isolation_report as sandbox_isolation_report
from srp.protocol.messages import (
    ActionPayload,
    ExecutionReceipt,
    MemoryPingChallenge,
    MemoryPingResponse,
    NodeCapabilities,
    SnapshotManifest,
    StepMetrics,
    StepObservation,
    StepResult,
    sha256_hex,
)

DEFAULT_STEP_TIMEOUT_MS = 5000
MAX_STEP_TIMEOUT_MS = 60000
MAX_BALLAST_PAGES = 1 << 20  # 4 GiB


class SRPProviderNode:
    """
    Contributor Node Daemon that donates/rents bounded volatile RAM capacity
    for AI model post-training (RLVR / GRPO / MCTS).
    """

    def __init__(
        self,
        node_id: str | None = None,
        ram_capacity_mb: int = 2048,
        node_secret: str | bytes | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self.node_id = node_id or f"srp_node_{uuid.uuid4().hex[:8]}"
        self.ram_capacity_mb = ram_capacity_mb
        self._keypair = (
            NodeKeypair.from_secret(node_secret) if node_secret is not None else NodeKeypair.generate()
        )
        self.public_key_hex = self._keypair.public_key_hex
        self.arena = VolatileRAMArena(capacity_mb=ram_capacity_mb)
        self.steps_executed: int = 0
        self.total_compute_ms: float = 0.0

    # --------------------------------------------------------------- identity
    def capabilities(self) -> NodeCapabilities:
        return NodeCapabilities(
            node_id=self.node_id,
            ram_arena_capacity_mb=self.ram_capacity_mb,
            public_key_hex=self.public_key_hex,
            sandbox_isolation=sandbox_isolation_report(),
        )

    def prove_key_possession(self, nonce: str) -> str:
        """Sign a coordinator registration nonce (NODE_REGISTER proof-of-possession)."""
        return self._keypair.sign(registration_message(self.node_id, self.public_key_hex, nonce))

    # -------------------------------------------------------------- snapshots
    def pin_snapshot(self, manifest: SnapshotManifest) -> PinnedSnapshot:
        """SRP_SNAPSHOT_PIN: Pin a base environment image into volatile 4KB RAM pages."""
        return self.arena.pin_snapshot(manifest)

    def pin_ballast(self, snapshot_id: str, pages: List[bytes]) -> int:
        """Hold explicit residency ballast pages for a snapshot."""
        return self.arena.pin_ballast(snapshot_id, pages)

    def pin_ballast_seed(self, snapshot_id: str, seed_hex: str, page_count: int) -> int:
        """SRP_BALLAST_PIN: expand a coordinator seed into sequential ballast pages."""
        if not 0 <= int(page_count) <= MAX_BALLAST_PAGES:
            raise ValueError(f"page_count must be within [0, {MAX_BALLAST_PAGES}]")
        pages = generate_ballast(bytes.fromhex(seed_hex), int(page_count))
        return self.arena.pin_ballast(snapshot_id, pages)

    def ballast_page_count(self, snapshot_id: str) -> int:
        return self.arena.ballast_page_count(snapshot_id)

    def evict_snapshot(self, snapshot_id: str, evict_branches: bool = True) -> int:
        """SRP_EVICT: Drop a pinned base snapshot and reclaim its unshared RAM pages."""
        return self.arena.evict_snapshot(snapshot_id=snapshot_id, evict_branches=evict_branches)

    # --------------------------------------------------------------- branches
    def fork(
        self,
        source_id: str,
        count: int = 1,
        ttl_seconds: Optional[float] = None,
        branch_ids: Optional[List[str]] = None,
    ) -> Tuple[List[CoWBranch], float]:
        """SRP_FORK: Create `count` Copy-on-Write rollout branches (ids may be coordinator-minted)."""
        return self.arena.fork(
            source_id=source_id, count=count, ttl_seconds=ttl_seconds, branch_ids=branch_ids
        )

    def step(
        self,
        branch_id: str,
        action: ActionPayload,
        request_id: str | None = None,
        timeout_ms: int = DEFAULT_STEP_TIMEOUT_MS,
    ) -> StepResult:
        """
        SRP_STEP: Execute a single RL environment step inside a CoW branch
        and return an Ed25519-signed ExecutionReceipt.
        """
        req_id = request_id or f"req_{uuid.uuid4().hex}"
        timeout_ms = int(max(1, min(int(timeout_ms), MAX_STEP_TIMEOUT_MS)))
        branch = self.arena.get_branch(branch_id)
        with branch._step_lock:
            if branch.evicted:
                raise KeyError(f"Branch '{branch_id}' was evicted before the step started")
            if branch.is_expired():
                expired = True
            else:
                expired = False
        if expired:
            self.arena.evict_branch(branch_id)
            raise KeyError(f"Branch '{branch_id}' expired (TTL) and was evicted")
        with branch._step_lock:
            if branch.evicted:
                raise KeyError(f"Branch '{branch_id}' was evicted before the step started")
            parent_state_hash = branch.state_hash
            prev_dirty_hashes = set(branch.dirty_page_hashes.keys())

            runtime = RUNTIME_ENGINES.get(branch.runtime)
            t0 = time.perf_counter()
            if runtime is None:
                observation = StepObservation(
                    stdout="", stderr=f"Unsupported runtime '{branch.runtime}'", exit_code=2
                )
                reward, terminated = 0.0, False
            else:
                observation, reward, terminated = runtime.execute_step(
                    branch, action, timeout_ms=timeout_ms
                )
            exec_ms = (time.perf_counter() - t0) * 1000.0
            reward = float(reward)
            if not math.isfinite(reward):
                observation = StepObservation(
                    stdout=observation.stdout,
                    stderr="Verifier produced a non-finite reward; coerced to 0.0",
                    exit_code=2,
                    structured_data={},
                )
                reward = 0.0

            step_dirty_pages = len(set(branch.dirty_page_hashes.keys()) - prev_dirty_hashes)
            branch.step_count += 1
            step_index = branch.step_count
            next_state_hash = branch.state_hash
            dirty_page_count = branch.dirty_page_count
            logical_bytes = branch.logical_bytes
            dirty_merkle_root = branch.dirty_page_merkle_root

        with self._lock:
            self.steps_executed += 1
            self.total_compute_ms += exec_ms

        metrics = StepMetrics(
            exec_time_ms=round(exec_ms, 4),
            dirty_pages=dirty_page_count,
            dirty_bytes=dirty_page_count * PAGE_SIZE,
            total_branch_ram_bytes=logical_bytes,
            step_dirty_pages=step_dirty_pages,
        )
        receipt = ExecutionReceipt(
            node_id=self.node_id,
            branch_id=branch.branch_id,
            parent_state_hash=parent_state_hash,
            action_hash=action.action_hash,
            next_state_hash=next_state_hash,
            dirty_page_merkle_root=dirty_merkle_root,
            stdout_hash=sha256_hex(observation.stdout),
            reward=reward,
            request_id=req_id,
            root_snapshot_id=branch.root_snapshot_id,
            step_index=step_index,
            terminated=bool(terminated),
            truncated=False,
            observation_hash=observation.canonical_hash(truncated=False),
            step_dirty_pages=step_dirty_pages,
            timeout_ms=timeout_ms,
        ).sign(self._keypair)

        return StepResult(
            request_id=req_id,
            branch_id=branch.branch_id,
            observation=observation,
            reward=reward,
            terminated=bool(terminated),
            truncated=False,
            metrics=metrics,
            receipt=receipt,
        )

    def evict_branch(self, branch_id: str) -> int:
        return self.arena.evict_branch(branch_id)

    def reap_expired(self) -> List[str]:
        return self.arena.reap_expired()

    def has_branch(self, branch_id: str) -> bool:
        with self.arena._lock:
            return branch_id in self.arena._branches

    # ------------------------------------------------------------- residency
    def handle_memory_ping(self, challenge: MemoryPingChallenge) -> MemoryPingResponse:
        return self.arena.answer_memory_ping(challenge, node_id=self.node_id)

    def telemetry(self) -> Dict[str, int | float | str]:
        with self._lock:
            stats = self.arena.stats()
            return {
                "node_id": self.node_id,
                "public_key_hex": self.public_key_hex,
                "steps_executed": self.steps_executed,
                "total_compute_ms": round(self.total_compute_ms, 2),
                **stats,
            }
