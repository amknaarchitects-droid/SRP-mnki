"""
SRP-002 Copy-on-Write (CoW) Volatile RAM Arena
==============================================
Implements a zero-disk-wear, 4KB page-granular Copy-on-Write memory engine.
- Base snapshots are chunked into immutable 4096-byte pages in volatile RAM.
- Forking a snapshot (or branching an existing branch for GRPO/MCTS tree search)
  copies only page table references in sub-millisecond time.
- Mutating files or linear memory inside a branch allocates new 4KB delta pages
  exclusively for the touched byte ranges.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from srp.protocol.messages import (
    MemoryPingChallenge,
    MemoryPingResponse,
    SnapshotManifest,
    compute_merkle_root,
    sha256_hex,
)

PAGE_SIZE = 4096  # Standard 4 KB hardware memory page


@dataclass(frozen=True)
class FileSliceRef:
    """Maps a virtual file in a snapshot/branch to its ordered list of 4KB page hashes."""

    path: str
    byte_length: int
    page_hashes: Tuple[str, ...]


class PinnedSnapshot:
    """
    Immutable base environment state ($S_0$) pinned in the node's volatile RAM Arena.
    """

    def __init__(
        self,
        manifest: SnapshotManifest,
        file_table: Dict[str, FileSliceRef],
        ordered_page_hashes: List[str],
        state_hash: str,
    ) -> None:
        self.manifest = manifest
        self.snapshot_id = manifest.snapshot_id
        self.suite = manifest.suite
        self.runtime = manifest.runtime
        self.file_table = dict(file_table)
        self.ordered_page_hashes = list(ordered_page_hashes)
        self.state_hash = state_hash
        self.pinned_at = time.time()

    @property
    def page_count(self) -> int:
        return len(self.ordered_page_hashes)

    @property
    def raw_bytes(self) -> int:
        return self.page_count * PAGE_SIZE


class CoWBranch:
    """
    A lightweight Copy-on-Write branch ($B_k$) forked from either a `PinnedSnapshot`
    or another `CoWBranch` (enabling tree-structured MCTS / GRPO rollouts).
    """

    def __init__(
        self,
        branch_id: str,
        root_snapshot_id: str,
        parent_id: str,
        suite: str,
        runtime: str,
        arena: "VolatileRAMArena",
        file_table: Dict[str, FileSliceRef],
        parent_state_hash: str,
    ) -> None:
        self.branch_id = branch_id
        self.root_snapshot_id = root_snapshot_id
        self.parent_id = parent_id
        self.suite = suite
        self.runtime = runtime
        self._arena = arena
        # Shallow copy of virtual file -> FileSliceRef pointers (zero data duplication)
        self.file_table: Dict[str, FileSliceRef] = dict(file_table)
        self.state_hash: str = parent_state_hash
        self.dirty_page_hashes: Dict[str, bytes] = {}
        self.step_count: int = 0
        self.created_at: float = time.time()

    def read_file(self, path: str) -> str:
        """Reconstruct a file from its 4KB RAM pages (base + CoW delta pages)."""
        if path not in self.file_table:
            raise FileNotFoundError(f"File '{path}' not found in CoW branch {self.branch_id}")
        fref = self.file_table[path]
        chunks: List[bytes] = []
        for phash in fref.page_hashes:
            page_bytes = self._arena.get_page_bytes(phash, self.dirty_page_hashes)
            chunks.append(page_bytes)
        raw = b"".join(chunks)[: fref.byte_length]
        return raw.decode("utf-8", errors="replace")

    def list_files(self) -> List[str]:
        return sorted(self.file_table.keys())

    def write_file(self, path: str, content: str | bytes) -> int:
        """
        Write or update a file using 4KB page-granular Copy-on-Write.
        Unchanged 4KB pages in the file continue referencing the parent's RAM frames!
        Returns the number of newly dirtied 4KB pages.
        """
        raw = content.encode("utf-8") if isinstance(content, str) else content
        if len(raw) > self._arena.free_ram_bytes:
            raise MemoryError(
                f"File write ({len(raw)} bytes) exceeds free volatile RAM arena capacity "
                f"({self._arena.free_ram_bytes} bytes)."
            )
        old_ref = self.file_table.get(path)
        old_hashes = set(old_ref.page_hashes) if old_ref else set()

        new_page_hashes: List[str] = []
        newly_dirtied = 0

        for offset in range(0, max(1, len(raw)), PAGE_SIZE):
            chunk = raw[offset : offset + PAGE_SIZE]
            if len(chunk) < PAGE_SIZE:
                chunk = chunk + b"\x00" * (PAGE_SIZE - len(chunk))
            phash = sha256_hex(chunk)
            new_page_hashes.append(phash)

            # Only allocate a dirty page if it isn't already in the shared base pool or branch
            if phash not in old_hashes and not self._arena.has_base_page(phash):
                if phash not in self.dirty_page_hashes:
                    self._arena.reserve_dirty_page( PAGE_SIZE )
                    self.dirty_page_hashes[phash] = chunk
                    newly_dirtied += 1

        self.file_table[path] = FileSliceRef(
            path=path,
            byte_length=len(raw),
            page_hashes=tuple(new_page_hashes),
        )
        self._recompute_state_hash()
        return newly_dirtied

    def delete_file(self, path: str) -> None:
        if path in self.file_table:
            del self.file_table[path]
            self._recompute_state_hash()

    def _recompute_state_hash(self) -> None:
        file_digests = [
            sha256_hex(f"{p}:{ref.byte_length}:{','.join(ref.page_hashes)}")
            for p, ref in sorted(self.file_table.items())
        ]
        self.state_hash = compute_merkle_root(file_digests)

    @property
    def dirty_page_count(self) -> int:
        return len(self.dirty_page_hashes)

    @property
    def dirty_bytes(self) -> int:
        return len(self.dirty_page_hashes) * PAGE_SIZE

    @property
    def dirty_page_merkle_root(self) -> str:
        return compute_merkle_root(sorted(self.dirty_page_hashes.keys()))


class VolatileRAMArena:
    """
    Bounded Volatile RAM Pool managing content-addressed 4KB base pages and
    Copy-on-Write branches with zero disk writes.
    """

    def __init__(self, capacity_mb: int = 4096) -> None:
        if capacity_mb <= 0:
            raise ValueError("capacity_mb must be positive")
        self.capacity_bytes: int = capacity_mb * 1024 * 1024
        self._base_pages: Dict[str, bytes] = {}
        self._snapshots: Dict[str, PinnedSnapshot] = {}
        self._branches: Dict[str, CoWBranch] = {}
        self._allocated_dirty_bytes: int = 0
        self.total_forks_created: int = 0

    @property
    def base_ram_bytes(self) -> int:
        return len(self._base_pages) * PAGE_SIZE

    @property
    def dirty_ram_bytes(self) -> int:
        return self._allocated_dirty_bytes

    @property
    def used_ram_bytes(self) -> int:
        return self.base_ram_bytes + self.dirty_ram_bytes

    @property
    def free_ram_bytes(self) -> int:
        return max(0, self.capacity_bytes - self.used_ram_bytes)

    def has_base_page(self, page_hash: str) -> bool:
        return page_hash in self._base_pages

    def get_page_bytes(self, page_hash: str, branch_dirty_pages: Dict[str, bytes]) -> bytes:
        if page_hash in branch_dirty_pages:
            return branch_dirty_pages[page_hash]
        if page_hash in self._base_pages:
            return self._base_pages[page_hash]
        raise KeyError(f"Memory page {page_hash[:12]} not found in volatile RAM arena")

    def reserve_dirty_page(self, num_bytes: int = PAGE_SIZE) -> None:
        if self.used_ram_bytes + num_bytes > self.capacity_bytes:
            raise MemoryError(
                f"SRP VolatileRAMArena ceiling reached ({self.capacity_bytes} bytes). "
                "Refusing allocation to prevent host OS disk swap."
            )
        self._allocated_dirty_bytes += num_bytes

    def pin_snapshot(self, manifest: SnapshotManifest) -> PinnedSnapshot:
        """
        Load a base snapshot into 4KB content-addressed volatile RAM pages.
        """
        if manifest.snapshot_id in self._snapshots:
            return self._snapshots[manifest.snapshot_id]

        file_table: Dict[str, FileSliceRef] = {}
        ordered_hashes: List[str] = []

        for path, content in sorted(manifest.initial_files.items()):
            raw = content.encode("utf-8")
            page_hashes: List[str] = []
            for offset in range(0, max(1, len(raw)), PAGE_SIZE):
                chunk = raw[offset : offset + PAGE_SIZE]
                if len(chunk) < PAGE_SIZE:
                    chunk = chunk + b"\x00" * (PAGE_SIZE - len(chunk))
                phash = sha256_hex(chunk)
                if phash not in self._base_pages:
                    if self.used_ram_bytes + PAGE_SIZE > self.capacity_bytes:
                        raise MemoryError("Insufficient free RAM in arena to pin snapshot")
                    self._base_pages[phash] = chunk
                page_hashes.append(phash)
                ordered_hashes.append(phash)

            file_table[path] = FileSliceRef(
                path=path,
                byte_length=len(raw),
                page_hashes=tuple(page_hashes),
            )

        file_digests = [
            sha256_hex(f"{p}:{ref.byte_length}:{','.join(ref.page_hashes)}")
            for p, ref in sorted(file_table.items())
        ]
        state_hash = compute_merkle_root(file_digests)

        snap = PinnedSnapshot(
            manifest=manifest,
            file_table=file_table,
            ordered_page_hashes=ordered_hashes,
            state_hash=state_hash,
        )
        self._snapshots[manifest.snapshot_id] = snap
        return snap

    def fork(self, source_id: str, count: int = 1) -> Tuple[List[CoWBranch], float]:
        """
        SRP_FORK: Create `count` Copy-on-Write branches from either a pinned
        base snapshot ID or an existing CoWBranch ID.
        Returns (branches, elapsed_ms).
        """
        t0 = time.perf_counter()
        branches: List[CoWBranch] = []

        if source_id in self._snapshots:
            snap = self._snapshots[source_id]
            for _ in range(count):
                bid = f"br_{uuid.uuid4().hex[:10]}"
                branch = CoWBranch(
                    branch_id=bid,
                    root_snapshot_id=snap.snapshot_id,
                    parent_id=snap.snapshot_id,
                    suite=snap.suite,
                    runtime=snap.runtime,
                    arena=self,
                    file_table=snap.file_table,
                    parent_state_hash=snap.state_hash,
                )
                self._branches[bid] = branch
                branches.append(branch)
                self.total_forks_created += 1

        elif source_id in self._branches:
            parent_branch = self._branches[source_id]
            # Promote parent's dirty pages into shared base pages so child branches share them CoW!
            for phash, pbytes in parent_branch.dirty_page_hashes.items():
                if phash not in self._base_pages:
                    self._base_pages[phash] = pbytes
            for _ in range(count):
                bid = f"br_{uuid.uuid4().hex[:10]}"
                branch = CoWBranch(
                    branch_id=bid,
                    root_snapshot_id=parent_branch.root_snapshot_id,
                    parent_id=parent_branch.branch_id,
                    suite=parent_branch.suite,
                    runtime=parent_branch.runtime,
                    arena=self,
                    file_table=parent_branch.file_table,
                    parent_state_hash=parent_branch.state_hash,
                )
                self._branches[bid] = branch
                branches.append(branch)
                self.total_forks_created += 1
        else:
            raise KeyError(f"Source snapshot or branch '{source_id}' not found in RAM Arena")

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return branches, elapsed_ms

    def get_branch(self, branch_id: str) -> CoWBranch:
        if branch_id not in self._branches:
            raise KeyError(f"Branch '{branch_id}' not found in RAM Arena")
        return self._branches[branch_id]

    def evict_branch(self, branch_id: str) -> int:
        """Drop a CoW branch and reclaim its dirty RAM pages."""
        branch = self._branches.pop(branch_id, None)
        if not branch:
            return 0
        reclaimed = len(branch.dirty_page_hashes) * PAGE_SIZE
        self._allocated_dirty_bytes = max(0, self._allocated_dirty_bytes - reclaimed)
        branch.dirty_page_hashes.clear()
        return reclaimed

    def answer_memory_ping(
        self, challenge: MemoryPingChallenge, node_id: str
    ) -> MemoryPingResponse:
        """
        SRP-003 Layer 3: Answer a random-page RAM residency challenge.
        """
        t0 = time.perf_counter()
        if challenge.snapshot_id not in self._snapshots:
            raise KeyError(f"Snapshot '{challenge.snapshot_id}' is not pinned in RAM")
        snap = self._snapshots[challenge.snapshot_id]
        total_pages = len(snap.ordered_page_hashes)
        if total_pages == 0:
            raise ValueError("Snapshot has 0 pages")

        sampled_indices: List[int] = []
        hasher = hashlib.sha256(challenge.nonce.encode("utf-8"))
        for i in range(challenge.sample_page_count):
            seed_bytes = hashlib.sha256(f"{challenge.nonce}:{i}".encode("utf-8")).digest()
            idx = int.from_bytes(seed_bytes[:4], "big") % total_pages
            sampled_indices.append(idx)
            phash = snap.ordered_page_hashes[idx]
            hasher.update(self._base_pages[phash])

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return MemoryPingResponse(
            challenge_id=challenge.challenge_id,
            node_id=node_id,
            snapshot_id=challenge.snapshot_id,
            sampled_page_indices=sampled_indices,
            combined_digest=hasher.hexdigest(),
            elapsed_ms=elapsed_ms,
        )

    def stats(self) -> Dict[str, int | float]:
        """Return real-time RAM efficiency and CoW compression statistics."""
        logical_bytes = sum(s.raw_bytes for s in self._snapshots.values())
        for b in self._branches.values():
            root_snap = self._snapshots.get(b.root_snapshot_id)
            if root_snap:
                logical_bytes += root_snap.raw_bytes
        physical_bytes = self.used_ram_bytes
        savings_ratio = (
            (1.0 - (physical_bytes / logical_bytes)) * 100.0
            if logical_bytes > 0 and logical_bytes >= physical_bytes
            else 0.0
        )
        return {
            "capacity_bytes": self.capacity_bytes,
            "base_ram_bytes": self.base_ram_bytes,
            "dirty_ram_bytes": self.dirty_ram_bytes,
            "used_ram_bytes": physical_bytes,
            "logical_unshared_bytes": logical_bytes,
            "cow_ram_savings_percent": round(savings_ratio, 2),
            "pinned_snapshots": len(self._snapshots),
            "active_branches": len(self._branches),
            "total_forks_created": self.total_forks_created,
        }
