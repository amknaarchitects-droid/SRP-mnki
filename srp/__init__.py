"""
Share RAM Protocol (SRP)
========================
An open-source public good protocol that turns idle consumer and workstation RAM
into a zero-disk-wear, Copy-on-Write (CoW) in-memory execution and verification
fabric for AI Reinforcement Learning (RL) post-training.
"""

__version__ = "0.4.0"

from srp.protocol.messages import (
    ActionPayload,
    ExecutionReceipt,
    FraudProof,
    MemoryPingChallenge,
    MemoryPingResponse,
    NodeCapabilities,
    SnapshotManifest,
    StepMetrics,
    StepObservation,
    StepResult,
)
from srp.node.ram_arena import CoWBranch, PinnedSnapshot, VolatileRAMArena, PAGE_SIZE
from srp.node.daemon import SRPProviderNode
from srp.coordinator.server import SRPCoordinator
from srp.settlement.base import (
    SettlementProvider,
    FiatAndApiCreditLedger,
    TokenEscrowLedger,
    OpenScienceKarmaLedger,
)
from srp.bridges.gym_bridge import SRPEnv, make, RolloutPool

__all__ = [
    "__version__",
    "PAGE_SIZE",
    "ActionPayload",
    "ExecutionReceipt",
    "FraudProof",
    "MemoryPingChallenge",
    "MemoryPingResponse",
    "NodeCapabilities",
    "SnapshotManifest",
    "StepMetrics",
    "StepObservation",
    "StepResult",
    "CoWBranch",
    "PinnedSnapshot",
    "VolatileRAMArena",
    "SRPProviderNode",
    "SRPCoordinator",
    "SettlementProvider",
    "FiatAndApiCreditLedger",
    "TokenEscrowLedger",
    "OpenScienceKarmaLedger",
    "SRPEnv",
    "make",
    "RolloutPool",
]
