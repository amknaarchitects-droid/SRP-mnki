"""
SRP-004 General Economic & Settlement Interface
===============================================
Protocol-fee-free (0% forever) pluggable settlement adapters so any AI lab,
startup, Web3 network, or university collective can reward RAM contributors
using their preferred economic model.

Economic security:
  * Nodes may (and coordinators may require them to) post a stake. Slashing
    draws from the earned balance first and then from the stake, so a fresh
    identity with no balance is still penalised.
  * RAM-lease value is only credited for intervals ending in a passed
    residency challenge (see `SRPCoordinator.verify_node_ram_residency`).
  * Payouts are closed in numbered epochs; each epoch's Merkle root covers only
    that epoch's unpaid amounts, so claims cannot be replayed across epochs.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Protocol, Tuple, runtime_checkable

from srp.protocol.messages import FraudProof, compute_merkle_root, sha256_hex

MICRO_UNITS = 1_000_000


@dataclass
class SettlementAccount:
    node_id: str
    pinned_gb_hours: float = 0.0
    verified_steps: int = 0
    total_dirty_pages_served: int = 0
    total_compute_ms: float = 0.0
    balance_units: float = 0.0
    stake_units: float = 0.0
    unbonding: List[Tuple[float, float]] = field(default_factory=list)  # (release_at, amount)
    slashed_units: float = 0.0
    settled_units: float = 0.0
    canary_failures: int = 0
    unit_symbol: str = "CREDITS"

    @property
    def unsettled_units(self) -> float:
        return max(0.0, round(self.balance_units - self.settled_units, 6))

    @property
    def unbonding_units(self) -> float:
        return round(sum(a for _, a in self.unbonding), 6)

    @property
    def bonded_units(self) -> float:
        """Stake that still backs this node (active + unbonding): all of it is slashable."""
        return round(self.stake_units + self.unbonding_units, 6)


@dataclass
class SettlementReceipt:
    receipt_id: str
    node_id: str
    delta_units: float
    new_balance: float
    unit_symbol: str
    reason: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class EpochPayout:
    """A closed payout epoch: `merkle_root` commits to every (node, amount) leaf."""

    epoch: int
    unit_symbol: str
    merkle_root: str
    leaves: List[Tuple[str, int]]  # (node_id, amount in micro-units)
    closed_at: float = field(default_factory=time.time)


def payout_leaf(epoch: int, node_id: str, amount_micro: int, unit_symbol: str) -> str:
    """Unambiguous, domain-separated payout leaf (JSON-encoded, no delimiter collisions)."""
    return sha256_hex(
        json.dumps(["SRP_PAYOUT_V1", epoch, node_id, amount_micro, unit_symbol], separators=(",", ":"))
    )


@runtime_checkable
class SettlementProvider(Protocol):
    """Universal interface for compensating SRP Provider Nodes."""

    unit_symbol: str

    def record_ram_lease(
        self, node_id: str, pinned_bytes: int, duration_seconds: float
    ) -> SettlementReceipt: ...

    def record_verified_step(
        self, node_id: str, compute_ms: float, dirty_pages: int
    ) -> SettlementReceipt: ...

    def record_canary_failure(self, node_id: str, fraud_proof: FraudProof) -> SettlementReceipt: ...

    def get_account(self, node_id: str) -> SettlementAccount: ...

    def summary(self) -> Dict[str, object]: ...


class BaseConfigurableLedger:
    """
    Base metering engine implementing the SRP-004 dual-component formula:
      Value = (alpha * verified GB_Hours) + (beta * Verified_Steps_Weighted)
    """

    def __init__(
        self,
        unit_symbol: str,
        rate_per_gb_hour: float,
        rate_per_step: float,
        rate_per_dirty_mb: float = 0.001,
        slash_penalty_units: float = 10.0,
        unbonding_period_s: float = 7 * 24 * 3600.0,
    ) -> None:
        self._lock = threading.RLock()
        self.unbonding_period_s = unbonding_period_s
        self._seq: int = 0
        self.unit_symbol = unit_symbol
        self.rate_per_gb_hour = rate_per_gb_hour
        self.rate_per_step = rate_per_step
        self.rate_per_dirty_mb = rate_per_dirty_mb
        self.slash_penalty_units = slash_penalty_units
        self._accounts: Dict[str, SettlementAccount] = {}
        self.ledger_history: List[SettlementReceipt] = []
        self.epochs: List[EpochPayout] = []

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _receipt(self, prefix: str, acct: SettlementAccount, delta: float, reason: str) -> SettlementReceipt:
        seq = self._next_seq()
        rec = SettlementReceipt(
            receipt_id=f"{prefix}_{sha256_hex(f'{acct.node_id}:{seq}:{time.time_ns()}')[:12]}",
            node_id=acct.node_id,
            delta_units=delta,
            new_balance=acct.balance_units,
            unit_symbol=self.unit_symbol,
            reason=reason,
        )
        self.ledger_history.append(rec)
        return rec

    def get_account(self, node_id: str) -> SettlementAccount:
        with self._lock:
            if node_id not in self._accounts:
                self._accounts[node_id] = SettlementAccount(node_id=node_id, unit_symbol=self.unit_symbol)
            return self._accounts[node_id]

    # ------------------------------------------------------------------ stake
    def deposit_stake(self, node_id: str, amount_units: float) -> SettlementReceipt:
        if amount_units <= 0:
            raise ValueError("Stake deposit must be positive")
        with self._lock:
            acct = self.get_account(node_id)
            acct.stake_units = round(acct.stake_units + amount_units, 6)
            return self._receipt("stake", acct, 0.0, f"Stake deposit: {amount_units:.6f}")

    def stake_of(self, node_id: str) -> float:
        """Active (not unbonding) stake: what counts toward routing requirements."""
        with self._lock:
            return self.get_account(node_id).stake_units

    def request_unbond(self, node_id: str, amount_units: float) -> SettlementReceipt:
        """Start unbonding stake. It stays slashable until the unbonding period ends."""
        with self._lock:
            acct = self.get_account(node_id)
            if not 0 < amount_units <= acct.stake_units + 1e-9:
                raise ValueError("Unbond amount must be positive and at most the active stake")
            acct.stake_units = round(acct.stake_units - amount_units, 6)
            acct.unbonding.append((time.time() + self.unbonding_period_s, round(amount_units, 6)))
            return self._receipt("unbond", acct, 0.0, f"Unbonding {amount_units:.6f}")

    def withdraw_unbonded(self, node_id: str, now: float | None = None) -> float:
        """Release stake whose unbonding period has elapsed; returns the amount."""
        now = time.time() if now is None else now
        with self._lock:
            acct = self.get_account(node_id)
            ready = [a for t, a in acct.unbonding if t <= now]
            acct.unbonding = [(t, a) for t, a in acct.unbonding if t > now]
            total = round(sum(ready), 6)
            if total:
                self._receipt("withdraw", acct, 0.0, f"Withdrew unbonded stake {total:.6f}")
            return total

    # ---------------------------------------------------------------- metering
    def record_ram_lease(self, node_id: str, pinned_bytes: int, duration_seconds: float) -> SettlementReceipt:
        if pinned_bytes < 0 or duration_seconds < 0:
            raise ValueError("pinned_bytes and duration_seconds must be non-negative")
        with self._lock:
            acct = self.get_account(node_id)
            gb_hours = (pinned_bytes / (1024 ** 3)) * (duration_seconds / 3600.0)
            earned = round(gb_hours * self.rate_per_gb_hour, 6)
            acct.pinned_gb_hours += gb_hours
            acct.balance_units = round(acct.balance_units + earned, 6)
            return self._receipt("stl", acct, earned, f"Verified RAM lease: {gb_hours:.6f} GB-hrs")

    def record_verified_step(self, node_id: str, compute_ms: float, dirty_pages: int) -> SettlementReceipt:
        with self._lock:
            acct = self.get_account(node_id)
            dirty_mb = (max(0, dirty_pages) * 4096) / (1024 * 1024)
            earned = round(self.rate_per_step + (dirty_mb * self.rate_per_dirty_mb), 6)
            acct.verified_steps += 1
            acct.total_dirty_pages_served += max(0, dirty_pages)
            acct.total_compute_ms += compute_ms
            acct.balance_units = round(acct.balance_units + earned, 6)
            return self._receipt(
                "stl", acct, earned,
                f"Verified RL step ({dirty_pages} CoW dirty pages, {compute_ms:.1f}ms)",
            )

    def record_canary_failure(self, node_id: str, fraud_proof: FraudProof) -> SettlementReceipt:
        """
        Slash for *provable* fraud only: the proof must be self-contained and
        third-party verifiable (signed receipt + replayable lineage). The penalty
        comes from the unsettled balance first, then from bonded stake (active,
        then unbonding). Already-paid-out earnings are never "clawed back" as a
        substitute for stake.
        """
        if not getattr(fraud_proof, "slashable", False):
            raise ValueError("Refusing to slash without a self-contained, verifiable FraudProof")
        if fraud_proof.node_id != node_id:
            raise ValueError("FraudProof does not concern this node")
        with self._lock:
            acct = self.get_account(node_id)
            acct.canary_failures += 1
            remaining = self.slash_penalty_units
            from_balance = min(acct.unsettled_units, remaining)
            acct.balance_units = round(acct.balance_units - from_balance, 6)
            remaining -= from_balance
            from_stake = min(acct.stake_units, remaining)
            acct.stake_units = round(acct.stake_units - from_stake, 6)
            remaining -= from_stake
            from_unbonding = 0.0
            new_unbonding = []
            for t, amount in sorted(acct.unbonding, reverse=True):  # latest releases first
                take = min(amount, max(0.0, remaining - from_unbonding))
                from_unbonding += take
                if amount - take > 1e-9:
                    new_unbonding.append((t, round(amount - take, 6)))
            acct.unbonding = sorted(new_unbonding)
            penalty = round(from_balance + from_stake + from_unbonding, 6)
            acct.slashed_units = round(acct.slashed_units + penalty, 6)
            return self._receipt(
                "slash", acct, -penalty,
                f"Fraud slashed ({from_balance:.6f} unsettled + {from_stake + from_unbonding:.6f} "
                f"stake): {fraud_proof.reason}",
            )

    def reverse_slash(self, node_id: str, amount_units: float, reason: str) -> SettlementReceipt:
        """Refund a slash overturned on appeal (credited back to stake)."""
        if amount_units < 0:
            raise ValueError("Refund must be non-negative")
        with self._lock:
            acct = self.get_account(node_id)
            acct.stake_units = round(acct.stake_units + amount_units, 6)
            acct.slashed_units = round(max(0.0, acct.slashed_units - amount_units), 6)
            acct.canary_failures = max(0, acct.canary_failures - 1)
            return self._receipt("refund", acct, amount_units, f"Slash reversed on appeal: {reason}")

    # ----------------------------------------------------------------- payouts
    def _pending_leaves(self, epoch: int) -> List[Tuple[str, int]]:
        leaves = []
        for nid, acct in sorted(self._accounts.items()):
            amount = int(round(acct.unsettled_units * MICRO_UNITS))
            if amount > 0:
                leaves.append((nid, amount))
        return leaves

    def compute_payout_merkle_root(self) -> str:
        """Preview of the Merkle root the *next* epoch would close with."""
        with self._lock:
            epoch = len(self.epochs) + 1
            leaves = self._pending_leaves(epoch)
            return compute_merkle_root(
                [payout_leaf(epoch, nid, amt, self.unit_symbol) for nid, amt in leaves]
            )

    def close_epoch(self) -> EpochPayout:
        """Close the current payout epoch and mark its amounts as settled."""
        with self._lock:
            epoch = len(self.epochs) + 1
            leaves = self._pending_leaves(epoch)
            root = compute_merkle_root(
                [payout_leaf(epoch, nid, amt, self.unit_symbol) for nid, amt in leaves]
            )
            for nid, amt in leaves:
                acct = self._accounts[nid]
                acct.settled_units = round(acct.settled_units + amt / MICRO_UNITS, 6)
            payout = EpochPayout(epoch=epoch, unit_symbol=self.unit_symbol, merkle_root=root, leaves=leaves)
            self.epochs.append(payout)
            return payout

    def summary(self) -> Dict[str, object]:
        with self._lock:
            return {
                "unit_symbol": self.unit_symbol,
                "total_accounts": len(self._accounts),
                "total_verified_steps": sum(a.verified_steps for a in self._accounts.values()),
                "total_balance_units": round(sum(a.balance_units for a in self._accounts.values()), 6),
                "total_settled_units": round(sum(a.settled_units for a in self._accounts.values()), 6),
                "total_slashed_units": round(sum(a.slashed_units for a in self._accounts.values()), 6),
                "closed_epochs": len(self.epochs),
                "accounts": {
                    nid: {
                        "balance": a.balance_units,
                        "stake": a.stake_units,
                        "unbonding": a.unbonding_units,
                        "unit": a.unit_symbol,
                        "verified_steps": a.verified_steps,
                        "dirty_pages_served": a.total_dirty_pages_served,
                        "canary_failures": a.canary_failures,
                        "slashed": a.slashed_units,
                    }
                    for nid, a in self._accounts.items()
                },
            }


class FiatAndApiCreditLedger(BaseConfigurableLedger):
    """
    Reference Settlement Plugin 1: AI Company USD / API Credit Ledger, for
    companies paying contributors in USD or API credits.
    """

    def __init__(
        self,
        unit_symbol: str = "USD_CREDITS",
        rate_per_gb_hour: float = 0.04,
        rate_per_step: float = 0.0005,
        slash_penalty_units: float = 10.0,
    ) -> None:
        super().__init__(
            unit_symbol=unit_symbol,
            rate_per_gb_hour=rate_per_gb_hour,
            rate_per_step=rate_per_step,
            slash_penalty_units=slash_penalty_units,
        )


class TokenEscrowLedger(BaseConfigurableLedger):
    """
    Reference Settlement Plugin 2: Web3 / Token Escrow Ledger (USDC or custom token).
    Each `close_epoch()` yields a Merkle root over that epoch's payout leaves that a
    claim contract can verify; leaves bind the epoch number, so a proof is valid
    for exactly one epoch.
    """

    def __init__(
        self,
        token_symbol: str = "SRP_USDC",
        rate_per_gb_hour: float = 0.05,
        rate_per_step: float = 0.001,
        slash_penalty_units: float = 10.0,
    ) -> None:
        super().__init__(
            unit_symbol=token_symbol,
            rate_per_gb_hour=rate_per_gb_hour,
            rate_per_step=rate_per_step,
            slash_penalty_units=slash_penalty_units,
        )


class OpenScienceKarmaLedger(BaseConfigurableLedger):
    """
    Reference Settlement Plugin 3: Non-Profit / Humanity Commons Karma Ledger for
    Folding@Home-style public-good AI post-training runs.
    """

    def __init__(self) -> None:
        super().__init__(
            unit_symbol="HUMANITY_KARMA",
            rate_per_gb_hour=100.0,
            rate_per_step=10.0,
        )
