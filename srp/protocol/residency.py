"""
SRP-003 Layer 3: WAN-Robust Residency Proofs
============================================
Two mechanisms make a residency challenge meaningful over a real network:

1. Sequential ballast (time-memory hard).
   Ballast page i is SHAKE-256 over (seed, i, page_{i-1}), so page i cannot be
   recomputed without page i-1. A node that drops the ballast and keeps only
   every m-th page as a checkpoint must re-hash ~m/2 pages for each lookup; a
   node that keeps nothing must regenerate from page 0. Honest RAM costs one
   memory read per lookup. The seed is derived from a coordinator-only secret
   and sent with SRP_BALLAST_PIN, so no bulk page transfer is needed.

2. Chained (pointer-chasing) challenges.
   Lookup t+1's index depends on the hash of the page read at lookup t, so the
   node must perform the lookups strictly sequentially: no prefetching and no
   parallel NVMe queue depth. Over `rounds` lookups, per-lookup latency
   differences between DRAM (~microseconds), swap (~100 us per random 4 KB
   read) and checkpoint recomputation (~100s of us) add up to milliseconds,
   which is well above WAN jitter. The coordinator subtracts a measured
   round-trip baseline before comparing against `max_lookup_us`.

The node returns the hash of every page it read. The coordinator re-derives the
entire index chain from those hashes (cheap), checks every snapshot-page hash
against the public manifest, and spot-checks a random subset of ballast hashes
using its own sparse checkpoints.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Callable, Dict, List, Sequence, Tuple

PAGE_SIZE = 4096
_DOMAIN = b"SRP_BALLAST_V2|"


def ballast_page(seed: bytes, index: int, previous: bytes) -> bytes:
    h = hashlib.shake_256(_DOMAIN + seed + b"|" + str(index).encode() + b"|" + previous)
    return h.digest(PAGE_SIZE)


def generate_ballast(seed: bytes, count: int) -> List[bytes]:
    """Generate `count` sequentially-dependent ballast pages (node side)."""
    pages: List[bytes] = []
    prev = b""
    for i in range(count):
        prev = ballast_page(seed, i, prev)
        pages.append(prev)
    return pages


class BallastCheckpoints:
    """Coordinator-side sparse ballast: stores every `stride`-th page, recomputes the rest."""

    def __init__(self, seed: bytes, count: int, stride: int = 32) -> None:
        if count < 0 or stride < 1:
            raise ValueError("invalid ballast parameters")
        self.seed, self.count, self.stride = seed, count, stride
        self._checkpoints: Dict[int, bytes] = {}
        prev = b""
        for i in range(count):
            prev = ballast_page(seed, i, prev)
            if i % stride == 0:
                self._checkpoints[i] = prev

    def page(self, index: int) -> bytes:
        if not 0 <= index < self.count:
            raise IndexError(index)
        base = index - (index % self.stride)
        page = self._checkpoints[base]
        for i in range(base + 1, index + 1):
            page = ballast_page(self.seed, i, page)
        return page


# --------------------------------------------------------------------------- #
# Chained challenge (shared by node and coordinator)                           #
# --------------------------------------------------------------------------- #
def _initial_state(nonce: str) -> bytes:
    return hashlib.sha256(b"SRP_CHAIN_V1|" + nonce.encode("utf-8")).digest()


def _next_target(state: bytes, t: int, n_snapshot: int, n_ballast: int) -> Tuple[str, int]:
    seed = int.from_bytes(state[:8], "big")
    if n_ballast and (t % 2 == 0 or n_snapshot == 0):
        return "b", seed % n_ballast
    if n_snapshot == 0:
        raise ValueError("challenge needs at least one snapshot or ballast page")
    return "s", seed % n_snapshot


def _advance(state: bytes, t: int, page_hash: bytes) -> bytes:
    return hashlib.sha256(state + page_hash + t.to_bytes(4, "big")).digest()


def answer_chain(
    nonce: str,
    rounds: int,
    n_snapshot: int,
    n_ballast: int,
    read_page: Callable[[str, int], bytes],
) -> Tuple[List[int], List[str], str]:
    """
    Node side: perform `rounds` sequential lookups.
    Returns (flat_indices, page_hashes_hex, final_digest_hex); a ballast index is
    reported as `n_snapshot + i`.
    """
    if rounds > 0 and n_snapshot == 0 and n_ballast == 0:
        raise ValueError("challenge needs at least one snapshot or ballast page")
    state = _initial_state(nonce)
    indices: List[int] = []
    hashes: List[str] = []
    for t in range(rounds):
        pool, idx = _next_target(state, t, n_snapshot, n_ballast)
        ph = hashlib.sha256(read_page(pool, idx)).digest()
        indices.append(idx if pool == "s" else n_snapshot + idx)
        hashes.append(ph.hex())
        state = _advance(state, t, ph)
    return indices, hashes, state.hex()


def verify_chain(
    nonce: str,
    rounds: int,
    n_snapshot: int,
    n_ballast: int,
    indices: Sequence[int],
    page_hashes: Sequence[str],
    final_digest: str,
    snapshot_page_hash: Callable[[int], str],
    ballast_page_bytes: Callable[[int], bytes],
    spot_checks: int = 32,
) -> Tuple[bool, str]:
    """
    Coordinator side. Re-derives the whole index chain from the reported page
    hashes, checks every snapshot lookup exactly, and spot-checks `spot_checks`
    random ballast lookups. Returns (ok, reason).
    """
    if len(indices) != rounds or len(page_hashes) != rounds:
        return False, "wrong number of lookups"
    state = _initial_state(nonce)
    ballast_steps: List[int] = []
    for t in range(rounds):
        pool, idx = _next_target(state, t, n_snapshot, n_ballast)
        expected_flat = idx if pool == "s" else n_snapshot + idx
        if indices[t] != expected_flat:
            return False, f"index chain broken at lookup {t}"
        try:
            ph = bytes.fromhex(page_hashes[t])
        except (ValueError, TypeError):
            return False, "malformed page hash"
        if len(ph) != 32:
            return False, "malformed page hash"
        if pool == "s":
            if page_hashes[t] != snapshot_page_hash(idx):
                return False, f"snapshot page mismatch at lookup {t}"
        else:
            ballast_steps.append(t)
        state = _advance(state, t, ph)
    if state.hex() != final_digest:
        return False, "final digest mismatch"
    rng = secrets.SystemRandom()
    for t in rng.sample(ballast_steps, min(spot_checks, len(ballast_steps))):
        idx = indices[t] - n_snapshot
        if hashlib.sha256(ballast_page_bytes(idx)).hexdigest() != page_hashes[t]:
            return False, f"ballast page mismatch at lookup {t}"
    return True, "ok"
