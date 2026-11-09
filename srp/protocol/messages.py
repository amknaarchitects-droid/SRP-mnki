"""
SRP-001 Wire Protocol Messages & Cryptographic Receipt Primitives.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_merkle_root(hashes: List[str]) -> str:
    """Compute a deterministic SHA-256 Merkle root from a list of hex hashes."""
    if not hashes:
        return sha256_hex(b"SRP_EMPTY_MERKLE_TREE")
    layer = list(hashes)
    while len(layer) > 1:
        next_layer: List[str] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if (i + 1) < len(layer) else left
            combined = f"{left}:{right}".encode("utf-8")
            next_layer.append(sha256_hex(combined))
        layer = next_layer
    return layer[0]


@dataclass
class NodeCapabilities:
    node_id: str
    ram_arena_capacity_mb: int
    supported_runtimes: List[str] = field(
        default_factory=lambda: ["wasm_cow", "container_tmpfs"]
    )
    supported_suites: List[str] = field(
        default_factory=lambda: [
            "srp-env-code",
            "srp-env-math",
            "srp-env-web",
            "srp-env-spatial",
        ]
    )
    public_key_hex: str = ""
    protocol_version: str = "0.1.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SnapshotManifest:
    snapshot_id: str
    suite: str
    runtime: str = "wasm_cow"
    initial_files: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def content_merkle_root(self) -> str:
        file_hashes = [
            sha256_hex(f"{path}:{content}")
            for path, content in sorted(self.initial_files.items())
        ]
        return compute_merkle_root(file_hashes)


@dataclass
class ActionPayload:
    command: str
    payload: Dict[str, Any] = field(default_factory=dict)

    @property
    def action_hash(self) -> str:
        canonical = json.dumps(
            {"command": self.command, "payload": self.payload},
            sort_keys=True,
            separators=(",", ":"),
        )
        return sha256_hex(canonical)


@dataclass
class StepObservation:
    stdout: str
    stderr: str = ""
    exit_code: int = 0
    structured_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StepMetrics:
    exec_time_ms: float
    dirty_pages: int
    dirty_bytes: int
    total_branch_ram_bytes: int


@dataclass
class ExecutionReceipt:
    """
    SRP-003 Cryptographic Proof-of-Execution & Memory State Transition Receipt.
    """

    node_id: str
    branch_id: str
    parent_state_hash: str
    action_hash: str
    next_state_hash: str
    dirty_page_merkle_root: str
    stdout_hash: str
    reward: float
    signature: str = ""

    def compute_canonical_digest(self) -> str:
        payload = (
            f"{self.node_id}|{self.branch_id}|{self.parent_state_hash}|"
            f"{self.action_hash}|{self.next_state_hash}|{self.dirty_page_merkle_root}|"
            f"{self.stdout_hash}|{self.reward:.8f}"
        )
        return sha256_hex(payload)

    def sign(self, node_secret: str) -> "ExecutionReceipt":
        digest = self.compute_canonical_digest()
        self.signature = hmac.new(
            node_secret.encode("utf-8"),
            digest.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return self

    def verify_signature(self, node_secret: str) -> bool:
        expected = hmac.new(
            node_secret.encode("utf-8"),
            self.compute_canonical_digest().encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected)


@dataclass
class StepResult:
    request_id: str
    branch_id: str
    observation: StepObservation
    reward: float
    terminated: bool
    truncated: bool
    metrics: StepMetrics
    receipt: ExecutionReceipt


@dataclass
class MemoryPingChallenge:
    """
    SRP-003 Layer 3 Anti-Swap Challenge: verifies that a pinned snapshot
    actually lives in physical DRAM and is not swapped out to a slow disk.
    """

    challenge_id: str
    snapshot_id: str
    nonce: str
    sample_page_count: int = 32
    max_latency_ms: float = 5.0


@dataclass
class MemoryPingResponse:
    challenge_id: str
    node_id: str
    snapshot_id: str
    sampled_page_indices: List[int]
    combined_digest: str
    elapsed_ms: float


@dataclass
class FraudProof:
    node_id: str
    request_id: str
    reason: str
    expected_reward: float
    actual_reward: float
    expected_state_hash: Optional[str] = None
    actual_state_hash: Optional[str] = None
    timestamp: float = 0.0
