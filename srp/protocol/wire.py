"""
SRP-001 Wire Codec (JSON-RPC 2.0)
=================================
Transport-agnostic encoding of SRP messages as UTF-8 JSON-RPC 2.0 frames.

Decoding is strict and never raises anything but `WireError`:
  * unknown methods, unknown fields, missing required fields, wrong
    protocol versions and oversized frames are rejected;
  * every field is type-checked against its dataclass annotation (no bool/int
    confusion, no strings where numbers are expected, floats must be finite,
    integers are length-limited);
  * per-field numeric ranges and list lengths are bounded;
  * nesting depth of free-form (`Any`) values is bounded.

Frame shape:
    {"jsonrpc": "2.0", "id": "<id>", "method": "SRP_STEP",
     "params": {"srp_version": "0.4.0", "body": {...dataclass fields...}}}
"""

from __future__ import annotations

import dataclasses
import json
import math
import typing
import uuid
from typing import Any, Dict, Optional, Tuple, Type

from srp.protocol.messages import (
    ActionPayload,
    BallastPin,
    EvictRequest,
    ExecutionReceipt,
    ForkAck,
    ForkRequest,
    FraudProof,
    MemoryPingChallenge,
    MemoryPingResponse,
    NodeCapabilities,
    SnapshotManifest,
    StepMetrics,
    StepObservation,
    StepRequest,
    StepResult,
)

PROTOCOL_VERSION = "0.4.0"
MAX_FRAME_BYTES = 16 * 1024 * 1024
MAX_LIST_ITEMS = 200_000
MAX_DEPTH = 32
MAX_INT_DIGITS = 40

MESSAGE_TYPES: Dict[str, Type[Any]] = {
    "NODE_REGISTER": NodeCapabilities,
    "SNAPSHOT_PIN": SnapshotManifest,
    "SRP_BALLAST_PIN": BallastPin,
    "SRP_FORK": ForkRequest,
    "SRP_FORK_ACK": ForkAck,
    "SRP_STEP": StepRequest,
    "SRP_STEP_RESULT": StepResult,
    "SRP_EVICT": EvictRequest,
    "SRP_MEMORY_PING": MemoryPingChallenge,
    "SRP_MEMORY_PING_RESPONSE": MemoryPingResponse,
    "SRP_FRAUD_PROOF": FraudProof,
}
_TYPE_TO_METHOD = {cls: name for name, cls in MESSAGE_TYPES.items()}

# Inclusive numeric bounds for fields that size work or memory on the receiver
_BOUNDS: Dict[Tuple[Type[Any], str], Tuple[float, float]] = {
    (ForkRequest, "branch_count"): (0, 4096),
    (ForkRequest, "ttl_seconds"): (0.001, 86_400.0),
    (StepRequest, "timeout_ms"): (1, 60_000),
    (MemoryPingChallenge, "sample_page_count"): (0, 65_536),
    (MemoryPingChallenge, "max_latency_ms"): (0.0, 3_600_000.0),
    (BallastPin, "page_count"): (0, 1 << 20),
    (NodeCapabilities, "ram_arena_capacity_mb"): (1, 1 << 24),
    (ExecutionReceipt, "step_index"): (0, 1 << 40),
    (ExecutionReceipt, "timeout_ms"): (0, 60_000),
    (ExecutionReceipt, "step_dirty_pages"): (0, 1 << 32),
}


class WireError(ValueError):
    """Raised for malformed, unknown, out-of-range or oversized frames."""


_HINTS: Dict[Type[Any], Dict[str, Any]] = {}


def _hints(cls: Type[Any]) -> Dict[str, Any]:
    if cls not in _HINTS:
        _HINTS[cls] = typing.get_type_hints(cls)
    return _HINTS[cls]


def _depth(value: Any, limit: int, level: int = 0) -> None:
    if level > limit:
        raise WireError("Value nesting exceeds MAX_DEPTH")
    if isinstance(value, dict):
        for v in value.values():
            _depth(v, limit, level + 1)
    elif isinstance(value, list):
        for v in value:
            _depth(v, limit, level + 1)


def _coerce(value: Any, tp: Any, where: str) -> Any:
    if tp is Any:
        _depth(value, MAX_DEPTH)
        return value
    origin = typing.get_origin(tp)
    args = typing.get_args(tp)
    if origin is typing.Union:
        if value is None:
            if type(None) in args:
                return None
            raise WireError(f"{where}: null not allowed")
        errors = []
        for a in args:
            if a is type(None):
                continue
            try:
                return _coerce(value, a, where)
            except WireError as exc:
                errors.append(str(exc))
        raise WireError(errors[0] if errors else f"{where}: invalid value")
    if dataclasses.is_dataclass(tp):
        return _from_dict(tp, value, where)
    if tp is bool:
        if not isinstance(value, bool):
            raise WireError(f"{where}: expected boolean")
        return value
    if tp is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise WireError(f"{where}: expected integer")
        return value
    if tp is float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise WireError(f"{where}: expected number")
        value = float(value)
        if not math.isfinite(value):
            raise WireError(f"{where}: number must be finite")
        return value
    if tp is str:
        if not isinstance(value, str):
            raise WireError(f"{where}: expected string")
        return value
    if origin in (list, typing.List):
        if not isinstance(value, list):
            raise WireError(f"{where}: expected list")
        if len(value) > MAX_LIST_ITEMS:
            raise WireError(f"{where}: list too long")
        (item_tp,) = args or (Any,)
        return [_coerce(v, item_tp, f"{where}[{i}]") for i, v in enumerate(value)]
    if origin in (dict, typing.Dict):
        if not isinstance(value, dict):
            raise WireError(f"{where}: expected object")
        key_tp, val_tp = args or (str, Any)
        return {_coerce(k, key_tp, f"{where}.key"): _coerce(v, val_tp, f"{where}.{k}") for k, v in value.items()}
    raise WireError(f"{where}: unsupported field type {tp!r}")


def _from_dict(cls: Type[Any], data: Any, where: str = "") -> Any:
    where = where or cls.__name__
    if not isinstance(data, dict):
        raise WireError(f"{where}: body must be an object")
    fields = {f.name: f for f in dataclasses.fields(cls)}
    unknown = set(data) - set(fields)
    if unknown:
        raise WireError(f"{where}: unknown fields {sorted(unknown)}")
    missing = [
        n for n, f in fields.items()
        if n not in data and f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING
    ]
    if missing:
        raise WireError(f"{where}: missing fields {missing}")
    hints = _hints(cls)
    kwargs: Dict[str, Any] = {}
    for name, value in data.items():
        value = _coerce(value, hints[name], f"{where}.{name}")
        bounds = _BOUNDS.get((cls, name))
        if bounds is not None and value is not None and not bounds[0] <= value <= bounds[1]:
            raise WireError(f"{where}.{name}: {value} outside [{bounds[0]}, {bounds[1]}]")
        kwargs[name] = value
    try:
        return cls(**kwargs)
    except Exception as exc:  # pragma: no cover - defensive
        raise WireError(f"Invalid {cls.__name__}: {exc}") from exc


def _parse_int(token: str) -> int:
    if len(token.lstrip("-")) > MAX_INT_DIGITS:
        raise WireError("Integer literal too long")
    return int(token)


def _parse_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise WireError(f"Non-finite number '{token}' is not allowed")
    return value


def _no_constants(token: str) -> Any:
    raise WireError(f"Non-finite number '{token}' is not allowed")


def encode_message(obj: Any, msg_id: Optional[str] = None, method: Optional[str] = None) -> str:
    """Serialise an SRP message dataclass into a JSON-RPC 2.0 frame."""
    method = method or _TYPE_TO_METHOD.get(type(obj))
    if method is None or not isinstance(obj, MESSAGE_TYPES[method]):
        raise WireError(f"Cannot encode {type(obj).__name__} as an SRP message")
    frame = {
        "jsonrpc": "2.0",
        "id": msg_id or uuid.uuid4().hex,
        "method": method,
        "params": {"srp_version": PROTOCOL_VERSION, "body": dataclasses.asdict(obj)},
    }
    try:
        text = json.dumps(frame, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise WireError(f"Message is not serialisable: {exc}") from exc
    if len(text.encode("utf-8")) > MAX_FRAME_BYTES:
        raise WireError("Frame exceeds MAX_FRAME_BYTES")
    return text


def decode_body(cls: Type[Any], body: Any) -> Any:
    """Validate a bare message body (used by transports for nested params)."""
    try:
        return _from_dict(cls, body)
    except WireError:
        raise
    except Exception as exc:
        raise WireError(f"Invalid {cls.__name__}: {exc}") from exc


def loads_strict(raw: str | bytes) -> Any:
    """json.loads with finite floats, bounded ints and WireError-only failures."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if len(raw) > MAX_FRAME_BYTES:
        raise WireError("Frame exceeds MAX_FRAME_BYTES")
    try:
        return json.loads(
            raw.decode("utf-8"), parse_constant=_no_constants,
            parse_float=_parse_float, parse_int=_parse_int,
        )
    except WireError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise WireError(f"Malformed frame: {type(exc).__name__}") from exc


def decode_message(frame: str | bytes) -> Tuple[str, Any, str]:
    """Parse and validate a frame; returns (method, message_object, msg_id)."""
    data = loads_strict(frame)
    try:
        if not isinstance(data, dict) or data.get("jsonrpc") != "2.0":
            raise WireError("Not a JSON-RPC 2.0 frame")
        method = data.get("method")
        if method not in MESSAGE_TYPES:
            raise WireError(f"Unknown SRP method '{method}'")
        params = data.get("params")
        version = params.get("srp_version") if isinstance(params, dict) else None
        if version != PROTOCOL_VERSION:
            raise WireError(f"Unsupported SRP protocol version {version!r}")
        msg_id = data.get("id")
        if not isinstance(msg_id, str) or not msg_id or len(msg_id) > 128:
            raise WireError("Frame id must be a non-empty string of at most 128 characters")
        return method, decode_body(MESSAGE_TYPES[method], params.get("body")), msg_id
    except WireError:
        raise
    except Exception as exc:  # pragma: no cover - defensive catch-all
        raise WireError(f"Invalid frame: {type(exc).__name__}") from exc


__all__ = [
    "PROTOCOL_VERSION", "MAX_FRAME_BYTES", "MESSAGE_TYPES", "WireError",
    "encode_message", "decode_message", "decode_body", "loads_strict",
]
