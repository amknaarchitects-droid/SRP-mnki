"""
SRP-004 General Economic & Settlement Interface
===============================================
Protocol-fee-free (0% forever) pluggable settlement adapters so any AI lab,
startup, Web3 network, or university collective can reward RAM contributors
using their preferred economic model.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Protocol, runtime_checkable

from srp.protocol.messages import FraudProof, sha256_hex


@dataclass
class SettlementAccount:
    node_id: str
    pinned_gb_hours: float = 0.0
    verified_steps: int = 0
    total_dirty_pages_served: int = 0
    total_compute_ms: float = 0.0
    balance_units: float = 0.0
    slashed_units: float = 0.0
    canary_failures: int = 0
    unit_symbol: str = "CREDITS"


@dataclass
class SettlementReceipt:
    receipt_id: str
    node_id: str
    delta_units: float
    new_balance: float
    unit_symbol: str
    reason: str
    timestamp: float = field(default_factory=time.time)


@runtime_checkable
class SettlementProvider(Protocol):
    """
    Universal interface for compensating SRP Provider Nodes.
    """

    unit_symbol: str

    def record_ram_lease(
        self, node_id: str, pinned_bytes: int, duration_seconds: float
    ) -> SettlementReceipt: ...

    def record_verified_step(
        self, node_id: str, compute_ms: float, dirty_pages: int
    ) -> SettlementReceipt: ...

    def record_canary_failure(
        self, node_id: str, fraud_proof: FraudProof
    ) -> SettlementReceipt: ...

    def get_account(self, node_id: str) -> SettlementAccount: ...

    def summary(self) -> Dict[str, object]: ...


class BaseConfigurableLedger:
    """
    Base metering engine implementing the SRP-004 dual-component formula:
      Value = (alpha * GB_Hours) + (beta * Verified_Steps_Weighted)
    """

    def __init__(
        self,
        unit_symbol: str,
        rate_per_gb_hour: float,
        rate_per_step: float,
        rate_per_dirty_mb: float = 0.001,
        slash_penalty_units: float = 10.0,
    ) -> None:
        self.unit_symbol = unit_symbol
        self.rate_per_gb_hour = rate_per_gb_hour
        self.rate_per_step = rate_per_step
        self.rate_per_dirty_mb = rate_per_dirty_mb
        self.slash_penalty_units = slash_penalty_units
        self._accounts: Dict[str, SettlementAccount] = {}
        self.ledger_history: List[SettlementReceipt] = []

    def get_account(self, node_id: str) -> SettlementAccount:
        if node_id not in self._accounts:
            self._accounts[node_id] = SettlementAccount(
                node_id=node_id, unit_symbol=self.unit_symbol
            )
        return self._accounts[node_id]

    def record_ram_lease(
        self, node_id: str, pinned_bytes: int, duration_seconds: float
    ) -> SettlementReceipt:
        acct = self.get_account(node_id)
        gb = pinned_bytes / (1024 ** 3)
        hours = duration_seconds / 3600.0
        gb_hours = gb * hours
        earned = round(gb_hours * self.rate_per_gb_hour, 6)

        acct.pinned_gb_hours += gb_hours
        acct.balance_units = round(acct.balance_units + earned, 6)

        rec = SettlementReceipt(
            receipt_id=f"stl_{sha256_hex(f'{node_id}:{time.time()}')[:10]}",
            node_id=node_id,
            delta_units=earned,
            new_balance=acct.balance_units,
            unit_symbol=self.unit_symbol,
            reason=f"RAM lease: {gb_hours:.6f} GB-hrs",
        )
        self.ledger_history.append(rec)
        return rec

    def record_verified_step(
        self, node_id: str, compute_ms: float, dirty_pages: int
    ) -> SettlementReceipt:
        acct = self.get_account(node_id)
        dirty_mb = (dirty_pages * 4096) / (1024 * 1024)
        earned = round(self.rate_per_step + (dirty_mb * self.rate_per_dirty_mb), 6)

        acct.verified_steps += 1
        acct.total_dirty_pages_served += dirty_pages
        acct.total_compute_ms += compute_ms
        acct.balance_units = round(acct.balance_units + earned, 6)

        rec = SettlementReceipt(
            receipt_id=f"stl_{sha256_hex(f'{node_id}:{acct.verified_steps}:{time.time()}')[:10]}",
            node_id=node_id,
            delta_units=earned,
            new_balance=acct.balance_units,
            unit_symbol=self.unit_symbol,
            reason=f"Verified RL step ({dirty_pages} CoW dirty pages, {compute_ms:.1f}ms)",
        )
        self.ledger_history.append(rec)
        return rec

    def record_canary_failure(
        self, node_id: str, fraud_proof: FraudProof
    ) -> SettlementReceipt:
        acct = self.get_account(node_id)
        acct.canary_failures += 1
        penalty = min(acct.balance_units, self.slash_penalty_units)
        acct.balance_units = round(max(0.0, acct.balance_units - penalty), 6)
        acct.slashed_units = round(acct.slashed_units + penalty, 6)

        rec = SettlementReceipt(
            receipt_id=f"slash_{sha256_hex(f'{node_id}:{fraud_proof.request_id}')[:10]}",
            node_id=node_id,
            delta_units=-penalty,
            new_balance=acct.balance_units,
            unit_symbol=self.unit_symbol,
            reason=f"Canary Fraud Slashed: {fraud_proof.reason}",
        )
        self.ledger_history.append(rec)
        return rec

    def summary(self) -> Dict[str, object]:
        return {
            "unit_symbol": self.unit_symbol,
            "total_accounts": len(self._accounts),
            "total_verified_steps": sum(a.verified_steps for a in self._accounts.values()),
            "total_distributed_units": round(
                sum(a.balance_units for a in self._accounts.values()), 6
            ),
            "accounts": {
                nid: {
                    "balance": a.balance_units,
                    "unit": a.unit_symbol,
                    "verified_steps": a.verified_steps,
                    "dirty_pages_served": a.total_dirty_pages_served,
                    "canary_failures": a.canary_failures,
                }
                for nid, a in self._accounts.items()
            },
        }


class FiatAndApiCreditLedger(BaseConfigurableLedger):
    """
    Reference Settlement Plugin 1: AI Company USD / API Credit Ledger.
    Allows companies like Anthropic, OpenAI, or inference clouds to pay users
    in USD or API token credits for their contributed RAM and RL rollout steps.
    """

    def __init__(
        self,
        unit_symbol: str = "USD_CREDITS",
        rate_per_gb_hour: float = 0.04,
        rate_per_step: float = 0.0005,
    ) -> None:
        super().__init__(
            unit_symbol=unit_symbol,
            rate_per_gb_hour=rate_per_gb_hour,
            rate_per_step=rate_per_step,
        )


class TokenEscrowLedger(BaseConfigurableLedger):
    """
    Reference Settlement Plugin 2: Web3 / Token Escrow Ledger (USDC or Custom Token).
    Computes a cryptographic Merkle claim root over all contributor balances so
    contributors can claim tokens permissionlessly on-chain.
    """

    def __init__(
        self,
        token_symbol: str = "SRP_USDC",
        rate_per_gb_hour: float = 0.05,
        rate_per_step: float = 0.001,
    ) -> None:
        super().__init__(
            unit_symbol=token_symbol,
            rate_per_gb_hour=rate_per_gb_hour,
            rate_per_step=rate_per_step,
        )

    def compute_payout_merkle_root(self) -> str:
        from srp.protocol.messages import compute_merkle_root

        leaves = [
            sha256_hex(f"{nid}:{acct.balance_units:.6f}:{self.unit_symbol}")
            for nid, acct in sorted(self._accounts.items())
        ]
        return compute_merkle_root(leaves)


class OpenScienceKarmaLedger(BaseConfigurableLedger):
    """
    Reference Settlement Plugin 3: Non-Profit / Humanity Commons Karma Ledger.
    Designed for universities, open-source collectives, and Folding@Home-style
    public-good AI post-training runs.
    """

    def __init__(self) -> None:
        super().__init__(
            unit_symbol="HUMANITY_KARMA",
            rate_per_gb_hour=100.0,
            rate_per_step=10.0,
        )
