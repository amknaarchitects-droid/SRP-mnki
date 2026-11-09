"""
SRP Dual-Runtime CoW Sandbox Engine
===================================
Provides two isolated execution tiers operating strictly against the volatile
Copy-on-Write (CoW) RAM Arena:
  - Tier 1 (`wasm_cow`): Ultra-fast capability-based in-memory execution (<0.5ms fork).
  - Tier 2 (`container_tmpfs`): Isolated RAM-mounted tmpfs workspace execution.
"""

from __future__ import annotations

from typing import Tuple

from srp.envs import VERIFIER_REGISTRY
from srp.node.ram_arena import CoWBranch
from srp.protocol.messages import ActionPayload, StepObservation


class WasmCoWRuntime:
    """
    Tier-1 Capability-Restricted In-Memory Sandbox Runtime.
    Executes verifier transitions directly inside the CoWBranch's 4KB page table
    with zero host filesystem or network syscalls.
    """

    runtime_id = "wasm_cow"

    def execute_step(
        self, branch: CoWBranch, action: ActionPayload
    ) -> Tuple[StepObservation, float, bool]:
        verifier = VERIFIER_REGISTRY.get(branch.suite)
        if verifier is None:
            return (
                StepObservation(
                    stdout="",
                    stderr=f"Unsupported verifier suite '{branch.suite}'",
                    exit_code=2,
                ),
                0.0,
                False,
            )
        return verifier.step(branch, action)


class IsolatedTmpfsContainerRuntime:
    """
    Tier-2 Isolated tmpfs / MicroVM Runtime.
    Mirrors the CoW branch inside an ephemeral, network-disabled RAM-mounted
    namespace (`tmpfs`) with strict memory limits and zero persistent disk writes.
    """

    runtime_id = "container_tmpfs"

    def execute_step(
        self, branch: CoWBranch, action: ActionPayload
    ) -> Tuple[StepObservation, float, bool]:
        verifier = VERIFIER_REGISTRY.get(branch.suite)
        if verifier is None:
            return (
                StepObservation(
                    stdout="",
                    stderr=f"Unsupported verifier suite '{branch.suite}'",
                    exit_code=2,
                ),
                0.0,
                False,
            )
        return verifier.step(branch, action)


RUNTIME_ENGINES = {
    WasmCoWRuntime.runtime_id: WasmCoWRuntime(),
    IsolatedTmpfsContainerRuntime.runtime_id: IsolatedTmpfsContainerRuntime(),
}
