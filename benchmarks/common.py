"""Shared helpers: workloads, percentiles, environment description, memory readings."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import platform
import sys
from typing import Any, Dict, List, Optional, Sequence

from srp.cli import build_default_manifests
from srp.coordinator.server import SRPCoordinator
from srp.protocol.messages import ActionPayload, SnapshotManifest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT_DIR = os.path.join(REPO_ROOT, "benchmarks", "results")

_CORRECT_CODE = (
    "def merge_intervals(intervals):\n"
    "    if not intervals:\n"
    "        return []\n"
    "    intervals = sorted(intervals, key=lambda x: x[0])\n"
    "    merged = [list(intervals[0])]\n"
    "    for s, e in intervals[1:]:\n"
    "        if s <= merged[-1][1]:\n"
    "            merged[-1][1] = max(merged[-1][1], e)\n"
    "        else:\n"
    "            merged.append([s, e])\n"
    "    return merged\n"
)

# One representative episode per bundled suite: manifest key -> ordered actions.
EPISODES: Dict[str, List[ActionPayload]] = {
    "code": [ActionPayload("apply_patch", {"code": _CORRECT_CODE})],
    "math": [
        ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"}),
        ActionPayload("apply_tactic", {"tactic": "omega"}),
    ],
    "web": [
        ActionPayload("fill_input", {"selector": "#coupon-input", "value": "HUMANITY2026"}),
        ActionPayload("click", {"selector": "#apply-btn"}),
        ActionPayload("click", {"selector": "#pay-btn"}),
    ],
    "cad": [
        ActionPayload(
            "add_primitive",
            {"primitive": {"type": "box", "center": [0.0, 0.0, 7.0], "size": [8.0, 10.0, 10.0]}},
        )
    ],
}


def manifests() -> Dict[str, SnapshotManifest]:
    return build_default_manifests()


def unaudited_coordinator(**kw: Any) -> SRPCoordinator:
    """A coordinator with canaries and replay audits switched off (pure execution path)."""
    kw.setdefault("canary_rate", 0.0)
    kw.setdefault("audit_rate", 0.0)
    kw.setdefault("audit_rewarded_steps", False)
    return SRPCoordinator(**kw)


def auditor_steps(coord: SRPCoordinator) -> int:
    return sum(a.node.steps_executed for a in coord._auditors.values())  # noqa: SLF001


def summarize(samples_ms: Sequence[float]) -> Dict[str, float]:
    """Nearest-rank percentiles over wall-clock samples in milliseconds."""
    data = sorted(samples_ms)
    if not data:
        return {"n": 0}

    def pct(p: float) -> float:
        rank = max(1, min(len(data), int(-(-p * len(data) // 100))))  # ceil
        return data[rank - 1]

    return {
        "n": len(data),
        "mean_ms": round(sum(data) / len(data), 4),
        "min_ms": round(data[0], 4),
        "p50_ms": round(pct(50), 4),
        "p95_ms": round(pct(95), 4),
        "p99_ms": round(pct(99), 4),
        "max_ms": round(data[-1], 4),
    }


def fmt_ms(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    return f"{value:.3f}" if value < 10 else f"{value:.1f}"


# ------------------------------------------------------------------ memory
def rss_bytes() -> Optional[int]:
    """Resident set size of this process, or None if it cannot be read."""
    try:
        import psutil  # type: ignore

        return int(psutil.Process().memory_info().rss)
    except Exception:
        pass
    try:
        with open("/proc/self/statm", "r", encoding="ascii") as fh:
            return int(fh.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except Exception:
        pass
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class Counters(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                    (name, ctypes.c_size_t)
                    for name in (
                        "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                        "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                        "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage",
                    )
                ]

            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
            if psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
                return int(counters.WorkingSetSize)
        except Exception:
            pass
    return None


def _total_ram_bytes() -> Optional[int]:
    try:
        import psutil  # type: ignore

        return int(psutil.virtual_memory().total)
    except Exception:
        pass
    try:
        return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except Exception:
        return None


def _cpu_model() -> str:
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or platform.machine()


def _git_commit() -> str:
    """Read HEAD without invoking git (works on checkouts git refuses to open)."""
    git_dir = os.path.join(REPO_ROOT, ".git")
    try:
        with open(os.path.join(git_dir, "HEAD"), "r", encoding="ascii") as fh:
            head = fh.read().strip()
        if not head.startswith("ref: "):
            return head[:12]
        ref = head[5:]
        ref_path = os.path.join(git_dir, *ref.split("/"))
        if os.path.exists(ref_path):
            with open(ref_path, "r", encoding="ascii") as fh:
                return fh.read().strip()[:12]
        with open(os.path.join(git_dir, "packed-refs"), "r", encoding="ascii") as fh:
            for line in fh:
                if line.strip().endswith(" " + ref):
                    return line.split()[0][:12]
    except Exception:
        pass
    return "unknown"


def environment() -> Dict[str, Any]:
    total = _total_ram_bytes()
    in_wsl = "microsoft" in platform.release().lower()
    return {
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": _git_commit(),
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "os": f"{platform.system()} {platform.release()}" + (" (WSL2)" if in_wsl else ""),
        "machine": platform.machine(),
        "cpu": _cpu_model(),
        "logical_cpus": os.cpu_count(),
        "total_ram_gb": round(total / 2**30, 1) if total else None,
    }


def write_json(out_dir: str, name: str, payload: Dict[str, Any]) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{name}.json")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def distinct_text_pages(num_pages: int, label: str = "base") -> str:
    """`num_pages` distinct 4096-character ASCII pages (no two share a content hash)."""
    return "".join(
        hashlib.sha256(f"{label}:{i}".encode("ascii")).hexdigest() * 64 for i in range(num_pages)
    )
