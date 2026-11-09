"""
SRP Provider Node Daemon
========================
Manages a contributor's shared volatile RAM Arena, executes Copy-on-Write
forking (`SRP_FORK`) and sandboxed RL steps (`SRP_STEP`), generates cryptographic
Merkle receipts, and answers Proof-of-Honest-RAM challenges.
"""

from __future__ import annotations

import secrets
import time
import uuid
from typing import Dict, List, Tuple

from srp.node.ram_arena import CoWBranch, PinnedSnapshot, VolatileRAMArena
from srp.node.runtimes import RUNTIME_ENGINES
from srp.protocol.messages import (
    ActionPayload,
    ExecutionReceipt,
    MemoryPingChallenge,
    MemoryPingResponse,
    NodeCapabilities,
    SnapshotManifest,
    StepMetrics,
    StepResult,
    sha256_hex,
)


class SRPProviderNode:
    """
    Contributor Node Daemon that donates/rents bounded volatile RAM capacity
    for AI model post-training (RLVR / GRPO / MCTS).
    """

    def __init__(
        self,
        node_id: str | None = None,
        ram_capacity_mb: int = 2048,
        node_secret: str | None = None,
    ) -> None:
        self.node_id = node_id or f"srp_node_{uuid.uuid4().hex[:8]}"
        self.ram_capacity_mb = ram_capacity_mb
        self._node_secret = node_secret or secrets.token_hex(32)
        self.public_key_hex = sha256_hex(self._node_secret)
        self.arena = VolatileRAMArena(capacity_mb=ram_capacity_mb)
        self.steps_executed: int = 0
        self.total_compute_ms: float = 0.0

    @property
    def secret_key(self) -> str:
        return self._node_secret

    def capabilities(self) -> NodeCapabilities:
        return NodeCapabilities(
            node_id=self.node_id,
            ram_arena_capacity_mb=self.ram_capacity_mb,
            public_key_hex=self.public_key_hex,
        )

    def pin_snapshot(self, manifest: SnapshotManifest) -> PinnedSnapshot:
        """SRP_SNAPSHOT_PIN: Pin a base environment image into volatile 4KB RAM pages."""
        return self.arena.pin_snapshot(manifest)

    def fork(self, source_id: str, count: int = 1) -> Tuple[List[CoWBranch], float]:
        """SRP_FORK: Create `count` Copy-on-Write rollout branches in RAM."""
        return self.arena.fork(source_id=source_id, count=count)

    def step(
        self,
        branch_id: str,
        action: ActionPayload,
        request_id: str | None = None,
    ) -> StepResult:
        """
        SRP_STEP: Execute a single RL environment step inside a CoW branch
        and return a signed cryptographic ExecutionReceipt.
        """
        req_id = request_id or f"req_{uuid.uuid4().hex[:8]}"
        branch = self.arena.get_branch(branch_id)
        parent_state_hash = branch.state_hash

        runtime = RUNTIME_ENGINES.get(branch.runtime, RUNTIME_ENGINES["wasm_cow"])

        t0 = time.perf_counter()
        observation, reward, terminated = runtime.execute_step(branch, action)
        exec_ms = (time.perf_counter() - t0) * 1000.0

        branch.step_count += 1
        self.steps_executed += 1
        self.total_compute_ms += exec_ms

        metrics = StepMetrics(
            exec_time_ms=round(exec_ms, 4),
            dirty_pages=branch.dirty_page_count,
            dirty_bytes=branch.dirty_bytes,
            total_branch_ram_bytes=branch.dirty_bytes,
        )

        receipt = ExecutionReceipt(
            node_id=self.node_id,
            branch_id=branch.branch_id,
            parent_state_hash=parent_state_hash,
            action_hash=action.action_hash,
            next_state_hash=branch.state_hash,
            dirty_page_merkle_root=branch.dirty_page_merkle_root,
            stdout_hash=sha256_hex(observation.stdout),
            reward=reward,
        ).sign(self._node_secret)

        return StepResult(
            request_id=req_id,
            branch_id=branch.branch_id,
            observation=observation,
            reward=reward,
            terminated=terminated,
            truncated=False,
            metrics=metrics,
            receipt=receipt,
        )

    def evict_branch(self, branch_id: str) -> int:
        return self.arena.evict_branch(branch_id)

    def handle_memory_ping(self, challenge: MemoryPingChallenge) -> MemoryPingResponse:
        return self.arena.answer_memory_ping(challenge, node_id=self.node_id)

    def telemetry(self) -> Dict[str, int | float | str]:
        stats = self.arena.stats()
        return {
            "node_id": self.node_id,
            "steps_executed": self.steps_executed,
            "total_compute_ms": round(self.total_compute_ms, 2),
            **stats,
        }
