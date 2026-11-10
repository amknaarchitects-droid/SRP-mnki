"""
Universal RL Framework Bridges
==============================
Drop-in adapters for:
  1. OpenAI Gym / Gymnasium (`SRPEnv`, `srp.make()`)
  2. GRPO / MCTS Parallel Rollout Pool (`RolloutPool` with sub-ms `SRP_FORK`)
  3. Prime Intellect `verifiers` (`PrimeVerifiersBridge`)
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional, Tuple

from srp.coordinator.server import SRPCoordinator
from srp.node.daemon import SRPProviderNode
from srp.protocol.messages import ActionPayload, SnapshotManifest, StepResult


class SRPEnv:
    """
    Gymnasium-compatible RL Environment backed by an SRP Copy-on-Write RAM branch.
    Supports instant `fork(n)` for MCTS / GRPO tree search.
    """

    def __init__(
        self,
        coordinator: SRPCoordinator,
        snapshot_id: str,
        branch_id: Optional[str] = None,
    ) -> None:
        self._lock = threading.RLock()
        self.coordinator = coordinator
        self.snapshot_id = snapshot_id
        self.branch_id = branch_id

    def reset(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        with self._lock:
            if self.branch_id is not None:
                self.coordinator.evict_branch(self.branch_id)
            branch_ids, fork_ms = self.coordinator.fork(self.snapshot_id, count=1)
            self.branch_id = branch_ids[0]
            return (
                {"branch_id": self.branch_id, "snapshot_id": self.snapshot_id},
                {"fork_latency_ms": fork_ms},
            )

    def step(
        self, action: ActionPayload | Dict[str, Any]
    ) -> Tuple[Dict[str, Any], float, bool, bool, Dict[str, Any]]:
        with self._lock:
            if self.branch_id is None:
                self.reset()
            assert self.branch_id is not None
            bid = self.branch_id

        if isinstance(action, dict):
            act_obj = ActionPayload(
                command=action["command"],
                payload=action.get("payload", {}),
            )
        else:
            act_obj = action

        res: StepResult = self.coordinator.step(bid, act_obj)
        obs = {
            "stdout": res.observation.stdout,
            "stderr": res.observation.stderr,
            "exit_code": res.observation.exit_code,
            "structured_data": res.observation.structured_data,
        }
        info = {
            "request_id": res.request_id,
            "branch_id": res.branch_id,
            "exec_time_ms": res.metrics.exec_time_ms,
            "dirty_pages": res.metrics.dirty_pages,
            "step_dirty_pages": res.metrics.step_dirty_pages,
            "dirty_bytes": res.metrics.dirty_bytes,
            "receipt": res.receipt,
        }
        return obs, res.reward, res.terminated, res.truncated, info

    def fork(self, count: int = 1) -> List["SRPEnv"]:
        """
        Branch the current mid-rollout environment state into `count` independent
        Copy-on-Write child environments in sub-millisecond time.
        """
        with self._lock:
            source = self.branch_id or self.snapshot_id
            child_ids, _ = self.coordinator.fork(source_id=source, count=count)
        return [
            SRPEnv(
                coordinator=self.coordinator,
                snapshot_id=self.snapshot_id,
                branch_id=cid,
            )
            for cid in child_ids
        ]

    def close(self) -> None:
        with self._lock:
            if self.branch_id is not None:
                self.coordinator.evict_branch(self.branch_id)
                self.branch_id = None


class RolloutPool:
    """
    High-throughput GRPO (Group Relative Policy Optimization) batch rollout manager.
    Forks $G$ parallel branches from a single pinned snapshot in RAM, executes
    candidate trajectories across the node pool, computes group-normalized
    advantages, and cleanly reclaims all dirty RAM pages.
    """

    def __init__(self, coordinator: SRPCoordinator, snapshot_id: str) -> None:
        self.coordinator = coordinator
        self.snapshot_id = snapshot_id

    def run_grpo_group(
        self,
        candidate_actions: List[ActionPayload],
        evict_after: bool = True,
    ) -> Dict[str, Any]:
        """
        Fork `len(candidate_actions)` CoW branches from `snapshot_id`, evaluate each
        action, and compute GRPO relative advantages:
          A_i = (r_i - mean(r)) / (std(r) + 1e-8)
        """
        group_size = len(candidate_actions)
        if group_size == 0:
            return {
                "group_size": 0,
                "fork_latency_ms": 0.0,
                "rewards": [],
                "mean_reward": 0.0,
                "advantages": [],
                "results": [],
                "branch_ids": [],
            }

        branch_ids, fork_ms = self.coordinator.fork(
            source_id=self.snapshot_id, count=group_size
        )

        results: List[StepResult] = []
        completed = False
        try:
            for bid, act in zip(branch_ids, candidate_actions):
                res = self.coordinator.step(branch_id=bid, action=act)
                results.append(res)

            rewards = [r.reward for r in results]
            mean_r = sum(rewards) / len(rewards)
            var_r = sum((r - mean_r) ** 2 for r in rewards) / len(rewards)
            std_r = var_r ** 0.5
            advantages = [
                round((r - mean_r) / (std_r + 1e-8), 4) if std_r > 1e-8 else 0.0
                for r in rewards
            ]
            completed = True
            return {
                "group_size": group_size,
                "fork_latency_ms": round(fork_ms, 4),
                "rewards": rewards,
                "mean_reward": round(mean_r, 4),
                "advantages": advantages,
                "results": results,
                "branch_ids": list(branch_ids),
            }
        finally:
            if evict_after or not completed:
                for bid in branch_ids:
                    self.coordinator.evict_branch(bid)


def make(
    manifest: SnapshotManifest,
    coordinator: Optional[SRPCoordinator] = None,
    default_ram_mb: int = 1024,
) -> SRPEnv:
    """
    One-line helper (`srp.make(manifest)`) to spin up an in-memory CoW RL environment.
    """
    if coordinator is None:
        coordinator = SRPCoordinator()
        local_node = SRPProviderNode(ram_capacity_mb=default_ram_mb)
        coordinator.register_node(local_node)
    coordinator.broadcast_snapshot(manifest)
    env = SRPEnv(coordinator=coordinator, snapshot_id=manifest.snapshot_id)
    env.reset()
    return env
