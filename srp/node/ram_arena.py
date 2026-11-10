"""
SRP-002 Copy-on-Write (CoW) Volatile RAM Arena
==============================================
Implements a zero-disk-wear, 4KB page-granular Copy-on-Write memory engine.
- Base snapshots are chunked into immutable 4096-byte pages in volatile RAM.
- Forking a snapshot (or branching an existing branch for GRPO/MCTS tree search)
  copies only page table references.
- Mutating files inside a branch allocates new 4KB delta pages exclusively for
  the touched byte ranges. Work per write is proportional to the size of the
  written file plus O(#files) for the state hash, not to the snapshot size.

Concurrency model / lock order (must always be acquired in this order):
    CoWBranch._step_lock  ->  VolatileRAMArena._lock
The arena lock is never held while waiting for a branch step lock.
"""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

from srp.protocol.residency import answer_chain
from srp.protocol.messages import (
    MemoryPingChallenge,
    MemoryPingResponse,
    SnapshotManifest,
    compute_merkle_root,
    chunk_file_into_4kb_pages,
    sha256_hex,
)

PAGE_SIZE = 4096  # Standard 4 KB hardware memory page

# Conservative estimates of interpreter bookkeeping charged against the RAM
# ceiling, so that page tables themselves cannot push the host into swap.
BRANCH_METADATA_BYTES = 2048
FILE_ENTRY_METADATA_BYTES = 160
DIRTY_REF_METADATA_BYTES = 96
PAGE_REF_METADATA_BYTES = 72
MAX_PING_ROUNDS = 65_536  # per page-hash entry in a file written by the branch


def _file_digest(path: str, byte_length: int, page_hashes: Iterable[str]) -> str:
    return sha256_hex(f"{path}:{byte_length}:{','.join(page_hashes)}")


@dataclass(frozen=True)
class FileSliceRef:
    """Maps a virtual file in a snapshot/branch to its ordered list of 4KB page hashes."""

    path: str
    byte_length: int
    page_hashes: Tuple[str, ...]


class PinnedSnapshot:
    """Immutable base environment state ($S_0$) pinned in the node's volatile RAM Arena."""

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
        self.file_digests: Dict[str, str] = {
            p: _file_digest(p, ref.byte_length, ref.page_hashes)
            for p, ref in self.file_table.items()
        }
        self.ordered_page_hashes = list(ordered_page_hashes)
        self.page_set = frozenset(self.ordered_page_hashes)
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

    Invariant: the branch holds an arena reference (in `dirty_page_hashes`) to
    every page in its file table that is not part of its own root snapshot.
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
        file_digests: Dict[str, str],
        initial_dirty_pages: Optional[Dict[str, bytes]] = None,
        nonroot_refs: Optional[Dict[str, int]] = None,
        expires_at: Optional[float] = None,
        owned_page_refs: Optional[Dict[str, int]] = None,
    ) -> None:
        self.branch_id = branch_id
        self.root_snapshot_id = root_snapshot_id
        self.parent_id = parent_id
        self.suite = suite
        self.runtime = runtime
        self._arena = arena
        self.file_table: Dict[str, FileSliceRef] = dict(file_table)
        self._file_digests: Dict[str, str] = dict(file_digests)
        self.state_hash: str = parent_state_hash
        self.dirty_page_hashes: Dict[str, bytes] = (
            dict(initial_dirty_pages) if initial_dirty_pages else {}
        )
        # Reference count of each non-root page across this branch's file table
        self._nonroot_refs: Dict[str, int] = dict(nonroot_refs) if nonroot_refs else {}
        # Page-table entries allocated by writes in this lineage (path -> #pages)
        self._owned_page_refs: Dict[str, int] = dict(owned_page_refs) if owned_page_refs else {}
        self.step_count: int = 0
        self.created_at: float = time.time()
        self.expires_at: Optional[float] = expires_at
        self.evicted: bool = False
        self._step_lock = threading.RLock()
        self._metadata_bytes: int = 0

    # ----------------------------------------------------------------- helpers
    def _check_alive(self) -> None:
        if self.evicted:
            raise KeyError(f"Branch '{self.branch_id}' has been evicted from the RAM Arena")

    def _compute_metadata_bytes(self) -> int:
        return (
            BRANCH_METADATA_BYTES
            + FILE_ENTRY_METADATA_BYTES * len(self.file_table)
            + DIRTY_REF_METADATA_BYTES * len(self.dirty_page_hashes)
            + PAGE_REF_METADATA_BYTES * sum(self._owned_page_refs.values())
        )

    def is_expired(self, now: Optional[float] = None) -> bool:
        return self.expires_at is not None and (now or time.time()) >= self.expires_at

    # ------------------------------------------------------------------- reads
    def read_bytes(self, path: str) -> bytes:
        """Reconstruct raw file bytes from its 4KB RAM pages (base + CoW delta pages)."""
        with self._arena._lock:
            self._check_alive()
            if path not in self.file_table:
                raise FileNotFoundError(
                    f"File '{path}' not found in CoW branch {self.branch_id}"
                )
            fref = self.file_table[path]
            chunks = [
                self._arena.get_page_bytes(ph, self.dirty_page_hashes)
                for ph in fref.page_hashes
            ]
            return b"".join(chunks)[: fref.byte_length]

    def read_file(self, path: str) -> str:
        """Reconstruct a UTF-8 file from its 4KB RAM pages (base + CoW delta pages)."""
        return self.read_bytes(path).decode("utf-8", errors="replace")

    def list_files(self) -> List[str]:
        with self._arena._lock:
            return sorted(self.file_table.keys())

    # ------------------------------------------------------------------ writes
    def _apply_nonroot_delta(
        self,
        old_nonroot: Counter,
        new_nonroot: Counter,
        new_page_map: Dict[str, bytes],
        extra_metadata_bytes: int,
    ) -> int:
        """Apply a refcount delta; enforce the RAM ceiling before mutating. Arena lock held."""
        arena = self._arena
        affected = set(old_nonroot) | set(new_nonroot)
        new_counts = {
            ph: self._nonroot_refs.get(ph, 0) - old_nonroot[ph] + new_nonroot[ph]
            for ph in affected
        }
        added = {ph for ph, c in new_counts.items() if c > 0 and ph not in self.dirty_page_hashes}
        removed = {ph for ph, c in new_counts.items() if c <= 0 and ph in self.dirty_page_hashes}

        new_arena_pages = sum(1 for ph in added if not arena.has_dirty_page(ph))
        freed_arena_pages = sum(
            1 for ph in removed if arena.is_sole_dirty_page_owner(ph, self.branch_id)
        )
        required = (
            (new_arena_pages - freed_arena_pages) * PAGE_SIZE
            + (len(added) - len(removed)) * DIRTY_REF_METADATA_BYTES
            + extra_metadata_bytes
        )
        if required > 0 and arena.committed_ram_bytes + required > arena.capacity_bytes:
            raise MemoryError(
                f"SRP VolatileRAMArena ceiling reached ({arena.capacity_bytes} bytes). "
                f"Write requires {required} bytes, but only {arena.free_ram_bytes} "
                "bytes are free. Refusing allocation to prevent host OS disk swap."
            )

        for ph in removed:
            self.dirty_page_hashes.pop(ph, None)
            arena._release_dirty_page(ph, self.branch_id)
        for ph in added:
            chunk = new_page_map.get(ph)
            if chunk is None:
                chunk = arena.get_page_bytes(ph, self.dirty_page_hashes)
            self.dirty_page_hashes[ph] = arena._retain_dirty_page(ph, chunk, self.branch_id)
        for ph, c in new_counts.items():
            if c > 0:
                self._nonroot_refs[ph] = c
            else:
                self._nonroot_refs.pop(ph, None)
        return len(added)

    def _refresh_accounting(self) -> None:
        new_meta = self._compute_metadata_bytes()
        self._arena._metadata_bytes += new_meta - self._metadata_bytes
        self._metadata_bytes = new_meta
        self.state_hash = compute_merkle_root(
            [self._file_digests[p] for p in sorted(self._file_digests)]
        )

    def write_file(self, path: str, content: str | bytes) -> int:
        """
        Write or update a file using 4KB page-granular Copy-on-Write.
        Unchanged 4KB pages keep referencing shared RAM frames; superseded dirty
        pages are reclaimed. Returns the number of newly dirtied pages in this branch.
        """
        byte_length, pages = chunk_file_into_4kb_pages(content, PAGE_SIZE)
        new_hashes = tuple(ph for ph, _ in pages)
        new_page_map = {ph: chunk for ph, chunk in pages}

        with self._arena._lock:
            self._check_alive()
            root_pages = self._arena._root_page_set(self.root_snapshot_id)
            old_ref = self.file_table.get(path)
            old_nonroot = Counter(
                ph for ph in (old_ref.page_hashes if old_ref else ()) if ph not in root_pages
            )
            new_nonroot = Counter(ph for ph in new_hashes if ph not in root_pages)
            extra_meta = (FILE_ENTRY_METADATA_BYTES if old_ref is None else 0) + (
                PAGE_REF_METADATA_BYTES
                * (len(new_hashes) - self._owned_page_refs.get(path, 0))
            )

            added = self._apply_nonroot_delta(old_nonroot, new_nonroot, new_page_map, extra_meta)
            self.file_table[path] = FileSliceRef(
                path=path, byte_length=byte_length, page_hashes=new_hashes
            )
            self._file_digests[path] = _file_digest(path, byte_length, new_hashes)
            self._owned_page_refs[path] = len(new_hashes)
            self._refresh_accounting()
            return added

    def delete_file(self, path: str) -> None:
        with self._arena._lock:
            self._check_alive()
            old_ref = self.file_table.get(path)
            if old_ref is None:
                return
            root_pages = self._arena._root_page_set(self.root_snapshot_id)
            old_nonroot = Counter(ph for ph in old_ref.page_hashes if ph not in root_pages)
            self._apply_nonroot_delta(old_nonroot, Counter(), {}, 0)
            del self.file_table[path]
            del self._file_digests[path]
            self._owned_page_refs.pop(path, None)
            self._refresh_accounting()

    # ----------------------------------------------------------------- metrics
    @property
    def dirty_page_count(self) -> int:
        with self._arena._lock:
            return len(self.dirty_page_hashes)

    @property
    def dirty_bytes(self) -> int:
        with self._arena._lock:
            return len(self.dirty_page_hashes) * PAGE_SIZE

    @property
    def logical_bytes(self) -> int:
        with self._arena._lock:
            return sum(len(ref.page_hashes) for ref in self.file_table.values()) * PAGE_SIZE

    @property
    def dirty_page_merkle_root(self) -> str:
        with self._arena._lock:
            return compute_merkle_root(sorted(self.dirty_page_hashes.keys()))


class VolatileRAMArena:
    """
    Bounded Volatile RAM Pool managing content-addressed 4KB base pages,
    Copy-on-Write branches and residency ballast with zero disk writes.

    Base, dirty and ballast pools are reference-counted independently. A page
    present in both the base and dirty pools is charged twice against the
    ceiling (conservative) but stored as a single bytes object.
    """

    def __init__(self, capacity_mb: int = 4096) -> None:
        if capacity_mb <= 0:
            raise ValueError("capacity_mb must be positive")
        self._lock = threading.RLock()
        self.capacity_bytes: int = capacity_mb * 1024 * 1024
        self._base_pages: Dict[str, bytes] = {}
        self._base_page_refs: Dict[str, Set[str]] = {}
        self._dirty_pages: Dict[str, bytes] = {}
        self._dirty_page_refs: Dict[str, Set[str]] = {}
        self._snapshots: Dict[str, PinnedSnapshot] = {}
        self._snapshot_meta: Dict[str, int] = {}
        self._evicting: Set[str] = set()
        self._evict_done = threading.Condition(self._lock)
        self._branches: Dict[str, CoWBranch] = {}
        self._branches_by_root: Dict[str, Set[str]] = {}
        self._ttl_branches: Set[str] = set()
        self._ballast: Dict[str, List[bytes]] = {}
        self._metadata_bytes: int = 0
        self.total_forks_created: int = 0

    # ------------------------------------------------------------- accounting
    @property
    def base_ram_bytes(self) -> int:
        with self._lock:
            return len(self._base_pages) * PAGE_SIZE

    @property
    def dirty_ram_bytes(self) -> int:
        with self._lock:
            return len(self._dirty_pages) * PAGE_SIZE

    @property
    def ballast_ram_bytes(self) -> int:
        with self._lock:
            return sum(len(p) for p in self._ballast.values()) * PAGE_SIZE

    @property
    def metadata_ram_bytes(self) -> int:
        with self._lock:
            return self._metadata_bytes

    @property
    def used_ram_bytes(self) -> int:
        """Bytes of page data held (base + dirty + ballast)."""
        with self._lock:
            return (
                len(self._base_pages) + len(self._dirty_pages)
            ) * PAGE_SIZE + self.ballast_ram_bytes

    @property
    def committed_ram_bytes(self) -> int:
        """Page data plus estimated bookkeeping; this is what the ceiling enforces."""
        with self._lock:
            return self.used_ram_bytes + self._metadata_bytes

    @property
    def free_ram_bytes(self) -> int:
        with self._lock:
            return max(0, self.capacity_bytes - self.committed_ram_bytes)

    def _ensure_capacity(self, extra_bytes: int, what: str) -> None:
        if self.committed_ram_bytes + extra_bytes > self.capacity_bytes:
            raise MemoryError(
                f"SRP VolatileRAMArena ceiling reached ({self.capacity_bytes} bytes): "
                f"{what} needs {extra_bytes} bytes, {self.free_ram_bytes} free. "
                "Refusing allocation to prevent host OS disk swap."
            )

    # ------------------------------------------------------------ page pools
    def has_base_page(self, page_hash: str) -> bool:
        with self._lock:
            return page_hash in self._base_pages

    def has_dirty_page(self, page_hash: str) -> bool:
        with self._lock:
            return page_hash in self._dirty_pages

    def is_sole_dirty_page_owner(self, page_hash: str, branch_id: str) -> bool:
        with self._lock:
            owners = self._dirty_page_refs.get(page_hash)
            return owners is not None and owners == {branch_id}

    def _root_page_set(self, snapshot_id: str) -> frozenset:
        """Pages guaranteed to outlive a branch: those of its own root snapshot."""
        with self._lock:
            snap = self._snapshots.get(snapshot_id)
            return snap.page_set if snap is not None else frozenset()

    def _retain_dirty_page(self, page_hash: str, page_bytes: bytes, branch_id: str) -> bytes:
        # A branch holds its own reference to every page outside its root snapshot,
        # even if another snapshot pins identical bytes: that snapshot can be
        # evicted independently of this branch.
        with self._lock:
            stored = self._dirty_pages.get(page_hash)
            if stored is None:
                stored = self._base_pages.get(page_hash, page_bytes)
                self._dirty_pages[page_hash] = stored
            self._dirty_page_refs.setdefault(page_hash, set()).add(branch_id)
            return stored

    def _release_dirty_page(self, page_hash: str, branch_id: str) -> None:
        with self._lock:
            owners = self._dirty_page_refs.get(page_hash)
            if owners is not None:
                owners.discard(branch_id)
                if not owners:
                    self._dirty_page_refs.pop(page_hash, None)
                    self._dirty_pages.pop(page_hash, None)

    def get_page_bytes(self, page_hash: str, branch_dirty_pages: Dict[str, bytes]) -> bytes:
        with self._lock:
            if page_hash in branch_dirty_pages:
                return branch_dirty_pages[page_hash]
            if page_hash in self._dirty_pages:
                return self._dirty_pages[page_hash]
            if page_hash in self._base_pages:
                return self._base_pages[page_hash]
            raise KeyError(f"Memory page {page_hash[:12]} not found in volatile RAM arena")

    def reserve_dirty_page(self, num_bytes: int = PAGE_SIZE) -> None:
        with self._lock:
            self._ensure_capacity(num_bytes, "page reservation")

    # ------------------------------------------------------------- snapshots
    def pin_snapshot(self, manifest: SnapshotManifest) -> PinnedSnapshot:
        """Load a base snapshot into 4KB content-addressed volatile RAM pages atomically."""
        ordered_hashes, page_map, state_hash = manifest.canonical_pages(PAGE_SIZE)
        with self._lock:
            if manifest.snapshot_id in self._evicting:
                raise RuntimeError(f"Snapshot '{manifest.snapshot_id}' is being evicted")
            existing = self._snapshots.get(manifest.snapshot_id)
            if existing is not None:
                if existing.state_hash != state_hash:
                    raise ValueError(
                        f"Snapshot id '{manifest.snapshot_id}' is already pinned with "
                        "different content; snapshot ids must be content-unique"
                    )
                return existing

            new_pages = {ph for ph in page_map if ph not in self._base_pages}
            snap_meta = (
                BRANCH_METADATA_BYTES
                + FILE_ENTRY_METADATA_BYTES * len(manifest.initial_files)
                + PAGE_REF_METADATA_BYTES * len(ordered_hashes)
            )
            self._ensure_capacity(len(new_pages) * PAGE_SIZE + snap_meta, "snapshot pin")

            file_table: Dict[str, FileSliceRef] = {}
            cursor = 0
            for path, content in sorted(manifest.initial_files.items()):
                raw = content.encode("utf-8") if isinstance(content, str) else content
                n_pages = max(1, -(-len(raw) // PAGE_SIZE))
                file_table[path] = FileSliceRef(
                    path=path,
                    byte_length=len(raw),
                    page_hashes=tuple(ordered_hashes[cursor : cursor + n_pages]),
                )
                cursor += n_pages

            for ph, chunk in page_map.items():
                # Reuse an identical dirty-page object so the bytes exist only once
                self._base_pages.setdefault(ph, self._dirty_pages.get(ph, chunk))
                self._base_page_refs.setdefault(ph, set()).add(manifest.snapshot_id)

            snap = PinnedSnapshot(
                manifest=manifest,
                file_table=file_table,
                ordered_page_hashes=ordered_hashes,
                state_hash=state_hash,
            )
            self._snapshots[manifest.snapshot_id] = snap
            self._snapshot_meta[manifest.snapshot_id] = snap_meta
            self._metadata_bytes += snap_meta
            self._branches_by_root.setdefault(manifest.snapshot_id, set())
            return snap

    def pin_ballast(self, snapshot_id: str, pages: List[bytes]) -> int:
        """Store node-unique residency ballast pages tied to a pinned snapshot."""
        if any(len(p) != PAGE_SIZE for p in pages):
            raise ValueError("Ballast pages must be exactly 4096 bytes")
        with self._lock:
            if snapshot_id in self._evicting:
                raise RuntimeError(f"Snapshot '{snapshot_id}' is being evicted")
            if snapshot_id not in self._snapshots:
                raise KeyError(f"Snapshot '{snapshot_id}' is not pinned")
            previous = len(self._ballast.get(snapshot_id, ()))
            self._ensure_capacity((len(pages) - previous) * PAGE_SIZE, "ballast pin")
            self._ballast[snapshot_id] = [bytes(p) for p in pages]
            return len(pages) * PAGE_SIZE

    def evict_snapshot(self, snapshot_id: str, evict_branches: bool = True) -> int:
        """
        SRP_EVICT: drop a pinned snapshot (+ballast) and reclaim its unshared pages.
        Concurrent calls for the same id are serialised: later callers wait for the
        first one to finish and then return 0.
        """
        with self._lock:
            while snapshot_id in self._evicting:
                self._evict_done.wait()
                if snapshot_id not in self._snapshots:
                    return 0
            if snapshot_id not in self._snapshots:
                return 0
            dependents = list(self._branches_by_root.get(snapshot_id, ()))
            if dependents and not evict_branches:
                raise RuntimeError(
                    f"Cannot evict snapshot '{snapshot_id}' while {len(dependents)} "
                    "active branches depend on it"
                )
            self._evicting.add(snapshot_id)  # blocks new pins, ballast and forks
        try:
            reclaimed = 0
            while True:
                # Evict outside the arena lock to respect the step-lock -> arena-lock order
                for bid in dependents:
                    reclaimed += self.evict_branch(bid)
                with self._lock:
                    dependents = list(self._branches_by_root.get(snapshot_id, ()))
                    if dependents:
                        continue
                    snap = self._snapshots.pop(snapshot_id, None)
                    if snap is None:
                        return reclaimed
                    for ph in snap.page_set:
                        refs = self._base_page_refs.get(ph)
                        if refs is not None:
                            refs.discard(snapshot_id)
                            if not refs:
                                self._base_page_refs.pop(ph, None)
                                if self._base_pages.pop(ph, None) is not None:
                                    reclaimed += PAGE_SIZE
                    reclaimed += len(self._ballast.pop(snapshot_id, ())) * PAGE_SIZE
                    self._metadata_bytes -= self._snapshot_meta.pop(snapshot_id, 0)
                    self._branches_by_root.pop(snapshot_id, None)
                    return reclaimed
        finally:
            with self._lock:
                self._evicting.discard(snapshot_id)
                self._evict_done.notify_all()

    # -------------------------------------------------------------- branches
    def fork(
        self,
        source_id: str,
        count: int = 1,
        ttl_seconds: Optional[float] = None,
        branch_ids: Optional[List[str]] = None,
    ) -> Tuple[List[CoWBranch], float]:
        """
        SRP_FORK: Create `count` Copy-on-Write branches from a pinned snapshot ID
        or an existing CoWBranch ID. Forking a branch is atomic with respect to
        steps on that branch. Returns (branches, elapsed_ms).
        """
        if count < 0:
            raise ValueError("count must be non-negative")
        if branch_ids is not None:
            if len(branch_ids) != count or len(set(branch_ids)) != count:
                raise ValueError("branch_ids must be `count` distinct ids")
            if any(not isinstance(b, str) or not b for b in branch_ids):
                raise ValueError("branch_ids must be non-empty strings")
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.reap_expired()
        t0 = time.perf_counter()
        expires_at = time.time() + ttl_seconds if ttl_seconds is not None else None

        with self._lock:
            parent_branch = self._branches.get(source_id)
            if parent_branch is None and source_id not in self._snapshots:
                raise KeyError(f"Source snapshot or branch '{source_id}' not found in RAM Arena")

        if parent_branch is not None:
            with parent_branch._step_lock:  # no fork mid-step
                return self._fork_locked(source_id, count, expires_at, t0, branch_ids)
        return self._fork_locked(source_id, count, expires_at, t0, branch_ids)

    def _new_branch_ids(self, count: int, requested: Optional[List[str]]) -> List[str]:
        if requested is None:
            return [f"br_{uuid.uuid4().hex[:16]}" for _ in range(count)]
        clash = [b for b in requested if b in self._branches or b in self._snapshots]
        if clash:
            raise ValueError(f"Branch id already in use: {clash[0]}")
        return list(requested)

    def _fork_locked(
        self,
        source_id: str,
        count: int,
        expires_at: Optional[float],
        t0: float,
        requested_ids: Optional[List[str]] = None,
    ) -> Tuple[List[CoWBranch], float]:
        branches: List[CoWBranch] = []
        with self._lock:
            new_ids = self._new_branch_ids(count, requested_ids)
            if source_id in self._snapshots:
                if source_id in self._evicting:
                    raise KeyError(f"Snapshot '{source_id}' is being evicted")
                snap = self._snapshots[source_id]
                per_branch = BRANCH_METADATA_BYTES + FILE_ENTRY_METADATA_BYTES * len(
                    snap.file_table
                )
                self._ensure_capacity(per_branch * count, f"fork of {count} branches")
                for bid in new_ids:
                    branches.append(
                        CoWBranch(
                            branch_id=bid,
                            root_snapshot_id=snap.snapshot_id,
                            parent_id=snap.snapshot_id,
                            suite=snap.suite,
                            runtime=snap.runtime,
                            arena=self,
                            file_table=snap.file_table,
                            parent_state_hash=snap.state_hash,
                            file_digests=snap.file_digests,
                            expires_at=expires_at,
                        )
                    )
            else:
                parent = self._branches.get(source_id)
                if parent is None or parent.evicted or parent.is_expired():
                    raise KeyError(f"Source snapshot or branch '{source_id}' not found in RAM Arena")
                if parent.root_snapshot_id in self._evicting:
                    raise KeyError(f"Root snapshot '{parent.root_snapshot_id}' is being evicted")
                self._ensure_capacity(
                    parent._compute_metadata_bytes() * count, f"fork of {count} branches"
                )
                for bid in new_ids:
                    branch = CoWBranch(
                        branch_id=bid,
                        root_snapshot_id=parent.root_snapshot_id,
                        parent_id=parent.branch_id,
                        suite=parent.suite,
                        runtime=parent.runtime,
                        arena=self,
                        file_table=parent.file_table,
                        parent_state_hash=parent.state_hash,
                        file_digests=parent._file_digests,
                        initial_dirty_pages=parent.dirty_page_hashes,
                        nonroot_refs=parent._nonroot_refs,
                        expires_at=expires_at,
                        owned_page_refs=parent._owned_page_refs,
                    )
                    for phash, pbytes in parent.dirty_page_hashes.items():
                        self._retain_dirty_page(phash, pbytes, branch.branch_id)
                    branches.append(branch)

            for branch in branches:
                branch._metadata_bytes = branch._compute_metadata_bytes()
                self._metadata_bytes += branch._metadata_bytes
                self._branches[branch.branch_id] = branch
                self._branches_by_root.setdefault(branch.root_snapshot_id, set()).add(
                    branch.branch_id
                )
                if branch.expires_at is not None:
                    self._ttl_branches.add(branch.branch_id)
                self.total_forks_created += 1

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return branches, elapsed_ms

    def get_branch(self, branch_id: str) -> CoWBranch:
        with self._lock:
            branch = self._branches.get(branch_id)
            if branch is None:
                raise KeyError(f"Branch '{branch_id}' not found in RAM Arena")
            expired = branch.is_expired()
        if expired:
            self.evict_branch(branch_id)
            raise KeyError(f"Branch '{branch_id}' expired (TTL) and was evicted")
        return branch

    def evict_branch(self, branch_id: str) -> int:
        """Drop a CoW branch and reclaim unshared dirty pages. Waits for an in-flight step."""
        with self._lock:
            branch = self._branches.get(branch_id)
            if branch is None:
                return 0
        with branch._step_lock:
            with self._lock:
                if self._branches.get(branch_id) is not branch:
                    return 0
                del self._branches[branch_id]
                self._branches_by_root.get(branch.root_snapshot_id, set()).discard(branch_id)
                self._ttl_branches.discard(branch_id)
                branch.evicted = True
                before = self.dirty_ram_bytes
                for phash in list(branch.dirty_page_hashes.keys()):
                    self._release_dirty_page(phash, branch_id)
                branch.dirty_page_hashes.clear()
                branch._nonroot_refs.clear()
                self._metadata_bytes -= branch._metadata_bytes
                branch._metadata_bytes = 0
                return max(0, before - self.dirty_ram_bytes)

    def reap_expired(self) -> List[str]:
        """Evict every branch whose TTL has elapsed; returns the evicted ids."""
        now = time.time()
        with self._lock:
            if not self._ttl_branches:
                return []
            expired = [
                bid
                for bid in self._ttl_branches
                if bid in self._branches and self._branches[bid].is_expired(now)
            ]
        for bid in expired:
            self.evict_branch(bid)
        return expired

    # ------------------------------------------------------- residency proof
    def ballast_page_count(self, snapshot_id: str) -> int:
        with self._lock:
            return len(self._ballast.get(snapshot_id, ()))

    def answer_memory_ping(
        self, challenge: MemoryPingChallenge, node_id: str
    ) -> MemoryPingResponse:
        """
        SRP-003 Layer 3: answer a chained (pointer-chasing) residency challenge
        over the snapshot pages and the snapshot's sequential ballast.
        """
        if not 0 <= challenge.sample_page_count <= MAX_PING_ROUNDS:
            raise ValueError(f"sample_page_count must be within [0, {MAX_PING_ROUNDS}]")
        t0 = time.perf_counter()
        with self._lock:
            if challenge.snapshot_id not in self._snapshots:
                raise KeyError(f"Snapshot '{challenge.snapshot_id}' is not pinned in RAM")
            snap = self._snapshots[challenge.snapshot_id]
            ballast = self._ballast.get(challenge.snapshot_id, [])
            base = self._base_pages
            ordered = snap.ordered_page_hashes

            def read(pool: str, idx: int) -> bytes:
                return ballast[idx] if pool == "b" else base[ordered[idx]]

            indices, hashes, digest = answer_chain(
                challenge.nonce, challenge.sample_page_count, snap.page_count, len(ballast), read
            )

        return MemoryPingResponse(
            challenge_id=challenge.challenge_id,
            node_id=node_id,
            snapshot_id=challenge.snapshot_id,
            sampled_page_indices=indices,
            combined_digest=digest,
            elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            page_hashes=hashes,
        )

    # ------------------------------------------------------------- telemetry
    def stats(self) -> Dict[str, int | float]:
        """Return real-time RAM efficiency and CoW compression statistics."""
        with self._lock:
            logical_bytes = sum(s.raw_bytes for s in self._snapshots.values())
            for b in self._branches.values():
                logical_bytes += b.logical_bytes
            physical_bytes = (len(self._base_pages) + len(self._dirty_pages)) * PAGE_SIZE
            savings_ratio = (
                (1.0 - (physical_bytes / logical_bytes)) * 100.0
                if logical_bytes > 0 and logical_bytes >= physical_bytes
                else 0.0
            )
            return {
                "capacity_bytes": self.capacity_bytes,
                "base_ram_bytes": self.base_ram_bytes,
                "dirty_ram_bytes": self.dirty_ram_bytes,
                "ballast_ram_bytes": self.ballast_ram_bytes,
                "metadata_ram_bytes": self._metadata_bytes,
                "used_ram_bytes": self.used_ram_bytes,
                "committed_ram_bytes": self.committed_ram_bytes,
                "logical_unshared_bytes": logical_bytes,
                "cow_ram_savings_percent": round(savings_ratio, 2),
                "pinned_snapshots": len(self._snapshots),
                "active_branches": len(self._branches),
                "total_forks_created": self.total_forks_created,
            }
