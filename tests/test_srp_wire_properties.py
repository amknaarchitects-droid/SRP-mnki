"""
Property-based tests for SRP-001 wire validation (v0.7).

Strategies are derived from the message dataclasses' type hints, so a new
field is covered automatically. The properties:

1. Every valid message survives encode -> decode unchanged.
2. Decoding never raises anything but `WireError`: not for arbitrary bytes,
   not for arbitrary JSON, and not for a valid frame with one field replaced
   by an arbitrary JSON value.
3. Numeric bounds and nesting limits are enforced.
4. The HTTP transport's method handlers (`NodeServer`) never fail with an
   unexpected exception type on arbitrary params: only the error types the
   transport is allowed to send back.
"""

from __future__ import annotations

import dataclasses
import json
import typing
from typing import Any, Dict

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from srp.protocol import wire  # noqa: E402
from srp.protocol.wire import (  # noqa: E402
    _BOUNDS,
    MAX_DEPTH,
    MESSAGE_TYPES,
    WireError,
    decode_body,
    decode_message,
    encode_message,
)

SETTINGS = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])

# ------------------------------------------------------------- strategies
_scalars = st.one_of(
    st.none(), st.booleans(), st.integers(-(10 ** 15), 10 ** 15),
    st.floats(allow_nan=False, allow_infinity=False), st.text(max_size=12),
)
json_values = st.recursive(
    _scalars,
    lambda inner: st.one_of(st.lists(inner, max_size=4), st.dictionaries(st.text(max_size=6), inner, max_size=4)),
    max_leaves=12,
)


def _for_type(tp: Any, cls: Any = None, name: str = "") -> st.SearchStrategy:
    bounds = _BOUNDS.get((cls, name))
    origin, args = typing.get_origin(tp), typing.get_args(tp)
    if tp is Any:
        return json_values
    if origin is typing.Union:
        inner = [a for a in args if a is not type(None)]
        return st.one_of(st.none(), *[_for_type(a, cls, name) for a in inner])
    if dataclasses.is_dataclass(tp):
        return _for_dataclass(tp)
    if tp is bool:
        return st.booleans()
    if tp is int:
        lo, hi = (int(bounds[0]), int(bounds[1])) if bounds else (-(10 ** 15), 10 ** 15)
        return st.integers(lo, hi)
    if tp is float:
        if bounds:
            return st.floats(bounds[0], bounds[1], allow_nan=False, allow_infinity=False)
        return st.floats(allow_nan=False, allow_infinity=False)
    if tp is str:
        return st.text(max_size=16)
    if origin in (list, typing.List):
        return st.lists(_for_type(args[0] if args else Any), max_size=3)
    if origin in (dict, typing.Dict):
        return st.dictionaries(st.text(max_size=8), _for_type(args[1] if args else Any), max_size=3)
    raise AssertionError(f"no strategy for {tp!r}")


def _for_dataclass(cls: Any) -> st.SearchStrategy:
    hints = typing.get_type_hints(cls)
    fields = {f.name: _for_type(hints[f.name], cls, f.name) for f in dataclasses.fields(cls)}
    return st.fixed_dictionaries(fields).map(lambda kw: cls(**kw))


messages = st.sampled_from(sorted(MESSAGE_TYPES)).flatmap(
    lambda method: st.tuples(st.just(method), _for_dataclass(MESSAGE_TYPES[method]))
)


def _only_wire_errors(fn, *args) -> None:
    try:
        fn(*args)
    except WireError:
        pass


# ----------------------------------------------------- 1. round trip
@SETTINGS
@given(messages)
def test_valid_messages_round_trip(item):
    method, msg = item
    decoded_method, decoded, _ = decode_message(encode_message(msg, msg_id="m1"))
    assert decoded_method == method
    assert decoded == msg


# ------------------------------------------ 2. only WireError escapes
@SETTINGS
@given(st.binary(max_size=512))
def test_arbitrary_bytes_raise_only_wire_errors(raw):
    _only_wire_errors(decode_message, raw)


@SETTINGS
@given(json_values)
def test_arbitrary_json_raises_only_wire_errors(value):
    _only_wire_errors(decode_message, json.dumps(value))


@SETTINGS
@given(st.sampled_from(sorted(MESSAGE_TYPES)), json_values)
def test_arbitrary_bodies_raise_only_wire_errors(method, body):
    frame = {"jsonrpc": "2.0", "id": "x", "method": method,
             "params": {"srp_version": wire.PROTOCOL_VERSION, "body": body}}
    _only_wire_errors(decode_message, json.dumps(frame))


@SETTINGS
@given(messages, st.data())
def test_one_corrupted_field_raises_only_wire_errors(item, data):
    method, msg = item
    frame = json.loads(encode_message(msg, msg_id="m1"))
    body: Dict[str, Any] = frame["params"]["body"]
    key = data.draw(st.sampled_from(sorted(body)))
    body[key] = data.draw(json_values)
    _only_wire_errors(decode_message, json.dumps(frame))


@SETTINGS
@given(st.sampled_from(sorted(MESSAGE_TYPES)), st.text(min_size=1, max_size=12))
def test_unknown_fields_are_rejected(method, extra):
    cls = MESSAGE_TYPES[method]
    if extra in {f.name for f in dataclasses.fields(cls)}:
        return
    with pytest.raises(WireError):
        decode_body(cls, {extra: 1})


# ------------------------------------------------- 3. bounds and depth
@SETTINGS
@given(st.sampled_from(sorted(_BOUNDS, key=lambda k: (k[0].__name__, k[1]))), st.data())
def test_out_of_range_numbers_are_rejected(key, data):
    cls, name = key
    lo, hi = _BOUNDS[key]
    is_int = typing.get_type_hints(cls)[name] is int
    if is_int:
        bad = data.draw(st.one_of(st.integers(max_value=int(lo) - 1), st.integers(min_value=int(hi) + 1)))
    else:
        bad = data.draw(st.one_of(st.floats(max_value=lo, exclude_max=True, allow_nan=False, allow_infinity=False),
                                  st.floats(min_value=hi, exclude_min=True, allow_nan=False, allow_infinity=False)))
    body = dataclasses.asdict(data.draw(_for_dataclass(cls)))
    body[name] = bad
    with pytest.raises(WireError):
        decode_body(cls, json.loads(json.dumps(body)))


@pytest.mark.parametrize("depth", [MAX_DEPTH + 1, MAX_DEPTH + 10, 500])
def test_free_form_values_nested_past_the_limit_are_rejected(depth):
    value: Any = 1
    for _ in range(depth):
        value = [value]
    with pytest.raises(WireError):
        decode_body(MESSAGE_TYPES["SNAPSHOT_PIN"], {"snapshot_id": "s", "suite": "x", "metadata": {"k": value}})


def test_nesting_at_the_limit_is_accepted():  # control
    value: Any = 1
    for _ in range(MAX_DEPTH - 1):
        value = [value]
    decode_body(MESSAGE_TYPES["SNAPSHOT_PIN"], {"snapshot_id": "s", "suite": "x", "metadata": {"k": value}})


# --------------------------------- 4. transport handlers on arbitrary params
@pytest.fixture(scope="module")
def node_server():
    from srp.cli import build_default_manifests
    from srp.node.daemon import SRPProviderNode
    from srp.protocol.crypto import NodeKeypair
    from srp.transport import NodeServer

    node = SRPProviderNode(node_id="prop1", ram_capacity_mb=64)
    node.pin_snapshot(build_default_manifests()["math"])
    server = NodeServer(node, NodeKeypair.generate().public_key_hex)
    yield server
    server._httpd.server_close()


ALLOWED_HANDLER_ERRORS = (WireError, KeyError, ValueError, PermissionError, MemoryError, RuntimeError)
_param_values = st.one_of(json_values, st.text(max_size=12), st.sampled_from(["snap_lean4_algebra_v1", "nope"]))


@SETTINGS
@given(st.data())
def test_transport_handlers_fail_only_with_allowed_errors(node_server, data):
    method = data.draw(st.sampled_from(sorted(node_server._methods)))
    keys = ["source_id", "count", "branch_ids", "ttl_seconds", "branch_id", "request_id", "timeout_ms",
            "action", "challenge", "snapshot_id", "seed_hex", "page_count", "nonce", "manifest",
            "evict_branches"]
    params = data.draw(st.dictionaries(st.sampled_from(keys), _param_values, max_size=6))
    try:
        node_server._methods[method](params)
    except ALLOWED_HANDLER_ERRORS:
        pass
