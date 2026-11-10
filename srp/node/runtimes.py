"""
SRP Sandbox Runtime Tiers
=========================
Both tiers operate strictly against the volatile Copy-on-Write (CoW) RAM Arena.

  - `wasm_cow`: in-process verifiers for declarative suites (math, web, CAD)
    whose actions are data, never code. Code-executing suites always delegate
    to the isolated subprocess sandbox in `srp.envs.sandbox`.
  - `container_tmpfs`: same verifier dispatch; on hosts with an OCI runtime this
    tier is where a container / microVM backend plugs in.

Security model: agent-supplied *code* never executes inside the node daemon's
process. See `srp/envs/sandbox.py` for the isolation guarantees and limits.
"""

from __future__ import annotations

from typing import Tuple

from srp.envs import VERIFIER_REGISTRY
from srp.node.ram_arena import CoWBranch
from srp.protocol.messages import ActionPayload, StepObservation


class _VerifierDispatchRuntime:
    runtime_id = ""

    def execute_step(
        self, branch: CoWBranch, action: ActionPayload, timeout_ms: int = 5000
    ) -> Tuple[StepObservation, float, bool]:
        verifier = VERIFIER_REGISTRY.get(branch.suite)
        if verifier is None:
            return (
                StepObservation(
                    stdout="", stderr=f"Unsupported verifier suite '{branch.suite}'", exit_code=2
                ),
                0.0,
                False,
            )
        return verifier.step(branch, action, timeout_ms=timeout_ms)


class WasmCoWRuntime(_VerifierDispatchRuntime):
    """Tier-1 capability-restricted in-memory runtime."""

    runtime_id = "wasm_cow"


class IsolatedTmpfsContainerRuntime(_VerifierDispatchRuntime):
    """Tier-2 isolated runtime (container / microVM backend plug-in point)."""

    runtime_id = "container_tmpfs"


RUNTIME_ENGINES = {
    WasmCoWRuntime.runtime_id: WasmCoWRuntime(),
    IsolatedTmpfsContainerRuntime.runtime_id: IsolatedTmpfsContainerRuntime(),
}
