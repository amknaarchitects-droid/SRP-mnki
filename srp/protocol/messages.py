"""
SRP-001 Wire Protocol Messages & Cryptographic Receipt Primitives.
"""

from __future__ import annotations

import hashlib
import json
import math
import platform
import sys
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

from srp.protocol.crypto import NodeKeypair, verify_signature


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    """Deterministic JSON used for every signed/hashed structure (rejects NaN/inf)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False, default=str)


def current_runtime_profile() -> str:
    """
    Identifies everything that can change verifier output for identical inputs:
    interpreter implementation + minor version (exception texts, recursion limits),
    the str-hash algorithm (set iteration order) and the OS (allocator/ASLR
    behaviour, resource-limit semantics). Nodes and the auditor that replays
    them must share a profile.
    """
    return (
        f"{platform.python_implementation().lower()}-"
        f"{sys.version_info.major}.{sys.version_info.minor}-"
        f"{sys.hash_info.algorithm}-{sys.platform}"
    )


def compute_merkle_root(hashes: List[str]) -> str:
    """
    Compute a deterministic, collision-resistant SHA-256 Merkle root from a list
    of hex hashes with leaf/internal/odd-node domain separation.
    """
    if not hashes:
        return sha256_hex(b"SRP_EMPTY_MERKLE_TREE")
    layer = [sha256_hex(f"leaf:{h}") for h in hashes]
    while len(layer) > 1:
        next_layer: List[str] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            if (i + 1) < len(layer):
                right = layer[i + 1]
                combined = f"node:{left}:{right}".encode("utf-8")
                next_layer.append(sha256_hex(combined))
            else:
                # Promote odd leaf with explicit domain separation instead of duplicating it
                next_layer.append(sha256_hex(f"odd:{left}".encode("utf-8")))
        layer = next_layer
    return layer[0]


def chunk_file_into_4kb_pages(
    content: str | bytes, page_size: int = 4096
) -> Tuple[int, List[Tuple[str, bytes]]]:
    """
    Deterministically chunk a file into zero-padded 4KB pages and return
    (raw_byte_length, [(page_hash, page_bytes), ...]).
    """
    raw = content.encode("utf-8") if isinstance(content, str) else content
    pages: List[Tuple[str, bytes]] = []
    for offset in range(0, max(1, len(raw)), page_size):
        chunk = raw[offset : offset + page_size]
        if len(chunk) < page_size:
            chunk = chunk + b"\x00" * (page_size - len(chunk))
        phash = sha256_hex(chunk)
        pages.append((phash, chunk))
    return len(raw), pages


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
    public_key_hex: str = ""  # Ed25519 public key (32 bytes, hex)
    protocol_version: str = "0.3.0"
    runtime_profile: str = field(default_factory=current_runtime_profile)
    sandbox_isolation: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SnapshotManifest:
    snapshot_id: str
    suite: str
    runtime: str = "wasm_cow"
    initial_files: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def canonical_pages(
        self, page_size: int = 4096
    ) -> Tuple[List[str], Dict[str, bytes], str]:
        """
        Return (ordered_page_hashes, page_map, state_hash) computed deterministically
        from `initial_files` using 4KB page chunking.
        """
        ordered_hashes: List[str] = []
        page_map: Dict[str, bytes] = {}
        file_digests: List[str] = []

        for path, content in sorted(self.initial_files.items()):
            byte_length, pages = chunk_file_into_4kb_pages(content, page_size=page_size)
            phashes: List[str] = []
            for phash, chunk in pages:
                page_map[phash] = chunk
                phashes.append(phash)
                ordered_hashes.append(phash)
            file_digests.append(
                sha256_hex(f"{path}:{byte_length}:{','.join(phashes)}")
            )

        state_hash = compute_merkle_root(file_digests)
        return ordered_hashes, page_map, state_hash

    @property
    def content_merkle_root(self) -> str:
        _, _, state_hash = self.canonical_pages()
        return state_hash


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

    def canonical_hash(self, truncated: bool = False) -> str:
        """Hash of everything a trainer consumes from the observation."""
        return sha256_hex(
            canonical_json(
                {
                    "stdout": self.stdout,
                    "stderr": self.stderr,
                    "exit_code": int(self.exit_code),
                    "structured_data": self.structured_data,
                    "truncated": bool(truncated),
                }
            )
        )


@dataclass
class StepMetrics:
    exec_time_ms: float
    dirty_pages: int
    dirty_bytes: int
    total_branch_ram_bytes: int
    step_dirty_pages: int = 0


@dataclass
class ExecutionReceipt:
    """
    SRP-003 Proof-of-Execution & Memory State Transition Receipt (V3).

    Signed by the executing node with its Ed25519 key. It binds the coordinator's
    `request_id`, the root snapshot and the per-branch `step_index` (no replay),
    the full observation (`observation_hash`), and every value the coordinator
    bills on (`step_dirty_pages`), so nothing a trainer or ledger consumes is
    unsigned.
    """

    node_id: str
    branch_id: str
    parent_state_hash: str
    action_hash: str
    next_state_hash: str
    dirty_page_merkle_root: str
    stdout_hash: str
    reward: float
    request_id: str = ""
    root_snapshot_id: str = ""
    step_index: int = 0
    terminated: bool = False
    truncated: bool = False
    observation_hash: str = ""
    step_dirty_pages: int = 0
    timeout_ms: int = 0
    signature_scheme: str = "ed25519"
    signature: str = ""

    def compute_canonical_digest(self) -> str:
        reward = float(self.reward)
        if not math.isfinite(reward):
            raise ValueError("receipt reward must be finite")
        payload = (
            f"SRP_RECEIPT_V3|{self.node_id}|{self.branch_id}|{self.request_id}|"
            f"{self.root_snapshot_id}|{int(self.step_index)}|{self.parent_state_hash}|"
            f"{self.action_hash}|{self.next_state_hash}|{self.dirty_page_merkle_root}|"
            f"{self.stdout_hash}|{reward:.8f}|{int(bool(self.terminated))}|"
            f"{int(bool(self.truncated))}|{self.observation_hash}|"
            f"{int(self.step_dirty_pages)}|{int(self.timeout_ms)}"
        )
        return sha256_hex(payload)

    def sign(self, keypair: "NodeKeypair") -> "ExecutionReceipt":
        self.signature_scheme = "ed25519"
        self.signature = keypair.sign(self.compute_canonical_digest().encode("utf-8"))
        return self

    def verify_signature(self, public_key_hex: str) -> bool:
        if self.signature_scheme != "ed25519" or not isinstance(self.signature, str):
            return False
        try:
            digest = self.compute_canonical_digest()
        except (ValueError, TypeError, OverflowError):
            return False
        return verify_signature(public_key_hex, digest.encode("utf-8"), self.signature)


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
    SRP-003 Layer 3 residency challenge. Samples are drawn alternately from the
    pinned snapshot pages and from node-unique *ballast* pages derived from a
    coordinator-only secret, so a node cannot answer by regenerating public
    manifest content: it must actually hold the ballast it was sent. Latency
    is measured by the coordinator, never self-reported.
    """

    challenge_id: str
    snapshot_id: str
    nonce: str
    sample_page_count: int = 64
    max_latency_ms: float = 5.0


@dataclass
class MemoryPingResponse:
    challenge_id: str
    node_id: str
    snapshot_id: str
    sampled_page_indices: List[int]
    combined_digest: str
    elapsed_ms: float
    page_hashes: List[str] = field(default_factory=list)


FRAUD_KIND_REPLAY = "replay_mismatch"
FRAUD_KIND_CANARY = "canary_mismatch"
SLASHABLE_FRAUD_KINDS = (FRAUD_KIND_REPLAY, FRAUD_KIND_CANARY)


@dataclass
class FraudProof:
    """
    Evidence of misbehaviour.

    Slashable proofs (`replay_mismatch`, `canary_mismatch`) are *self-contained*:
    they carry the node-signed receipt plus the full lineage (root snapshot,
    its content hash, every action and its timeout). Because suites are
    deterministic under a runtime profile, any third party can replay the
    lineage and confirm the signed receipt is wrong; see
    `srp.coordinator.server.verify_fraud_proof_by_replay`.
    Other kinds (protocol faults) justify quarantine but are not slashable.
    """

    node_id: str
    request_id: str
    reason: str
    expected_reward: float
    actual_reward: float
    expected_state_hash: Optional[str] = None
    actual_state_hash: Optional[str] = None
    timestamp: float = 0.0
    receipt: Optional[ExecutionReceipt] = None
    node_public_key_hex: str = ""
    kind: str = "protocol_fault"
    root_snapshot_id: str = ""
    root_content_hash: str = ""
    lineage: List[Dict[str, Any]] = field(default_factory=list)
    runtime_profile: str = ""
    trusted_observation_hash: str = ""

    def is_third_party_verifiable(self) -> bool:
        if self.receipt is None or not self.node_public_key_hex:
            return False
        if self.receipt.node_id != self.node_id:
            return False
        if not self.receipt.verify_signature(self.node_public_key_hex):
            return False
        if self.kind in SLASHABLE_FRAUD_KINDS:
            return bool(self.root_snapshot_id and self.root_content_hash and self.lineage)
        return False

    @property
    def slashable(self) -> bool:
        return self.kind in SLASHABLE_FRAUD_KINDS and self.is_third_party_verifiable()


@dataclass
class ForkRequest:
    """SRP_FORK (Coordinator -> Provider). Branch ids are minted by the coordinator."""

    source_id: str
    branch_count: int = 1
    ttl_seconds: Optional[float] = None
    branch_ids: List[str] = field(default_factory=list)


@dataclass
class ForkAck:
    """SRP_FORK_ACK (Provider -> Coordinator)."""

    source_id: str
    branch_ids: List[str]
    fork_latency_ms: float
    state_hash: str
    dirty_ram_bytes: int = 0
    root_snapshot_id: str = ""


@dataclass
class StepRequest:
    """SRP_STEP (Coordinator -> Provider)."""

    request_id: str
    branch_id: str
    action: ActionPayload
    timeout_ms: int = 5000


@dataclass
class EvictRequest:
    """SRP_EVICT (Coordinator -> Provider)."""

    snapshot_ids: List[str] = field(default_factory=list)
    branch_ids: List[str] = field(default_factory=list)


@dataclass
class BallastPin:
    """
    SRP_BALLAST_PIN: seed for node-unique, sequentially-dependent ballast pages
    (see `srp.protocol.residency`). The node expands the seed locally.
    """

    snapshot_id: str
    seed_hex: str
    page_count: int
