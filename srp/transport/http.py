"""
SRP HTTP JSON-RPC Transport (multi-host deployments)
====================================================
`NodeServer` exposes an `SRPProviderNode` over HTTP(S); `RemoteNode` is a drop-in
client the coordinator can register exactly like a local node.

Security properties:
  * Command authentication: every request is an Ed25519-signed envelope from
    the node's *configured* coordinator key, bound to the node id, method,
    params, request id, a timestamp (bounded clock skew) and a single-use nonce.
    Anyone else who can reach the port gets 401. Replays get 409.
  * Response authentication: every response (including errors) is signed by the
    node key, so a network attacker cannot forge fork acks, ping answers or
    errors. Step receipts carry their own Ed25519 signature as well.
  * Strict decoding: bodies go through `srp.protocol.wire` validation, frames
    are size-limited, and only an allow-listed set of exception types crosses
    the wire.
  * Confidentiality: pass an `ssl.SSLContext` to both sides for TLS (mTLS if the
    server context requires client certificates).
  * Deadlines: client calls time out (`timeout_s`), so a slow or hung node
    cannot stall the coordinator indefinitely.
"""

from __future__ import annotations

import dataclasses
import json
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Tuple

from srp.node.daemon import SRPProviderNode
from srp.protocol.crypto import NodeKeypair, verify_signature
from srp.protocol.messages import (
    ActionPayload,
    MemoryPingChallenge,
    MemoryPingResponse,
    NodeCapabilities,
    SnapshotManifest,
    StepResult,
    canonical_json,
)
from srp.protocol.wire import MAX_FRAME_BYTES, WireError, decode_body, loads_strict

RPC_PATH = "/srp/v1"
MAX_CLOCK_SKEW_S = 60.0
CONNECTION_TIMEOUT_S = 30.0  # per-connection socket timeout (slow clients / stalled TLS)
_ALLOWED_ERRORS = {
    "KeyError": KeyError, "PermissionError": PermissionError, "MemoryError": MemoryError,
    "ValueError": ValueError, "RuntimeError": RuntimeError, "WireError": WireError,
}


def _command_message(node_id: str, method: str, params: Any, req_id: str, ts: float, nonce: str) -> bytes:
    return ("SRP_CMD_V1|" + canonical_json(
        {"node_id": node_id, "method": method, "params": params, "id": req_id, "ts": ts, "nonce": nonce}
    )).encode("utf-8")


def _response_message(req_id: str, payload: Any) -> bytes:
    return ("SRP_RESP_V1|" + req_id + "|" + canonical_json(payload)).encode("utf-8")


class _NonceCache:
    def __init__(self, window_s: float) -> None:
        self.window_s = window_s
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()

    def use(self, nonce: str, now: float) -> bool:
        with self._lock:
            for n in [n for n, t in self._seen.items() if now - t > 2 * self.window_s]:
                del self._seen[n]
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True


class _TLSThreadingHTTPServer(ThreadingHTTPServer):
    """
    Threading HTTP(S) server that performs the TLS handshake in the
    per-connection worker thread, under that connection's socket timeout.

    Wrapping the *listening* socket would run the handshake inside `accept()`
    on the single serve thread, so one client that connects and never sends a
    ClientHello would stall every other request.
    """

    def __init__(self, addr, handler, ssl_context: Optional[ssl.SSLContext]) -> None:
        self.ssl_context = ssl_context
        super().__init__(addr, handler)

    def get_request(self):
        sock, addr = super().get_request()
        if self.ssl_context is not None:
            sock = self.ssl_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return sock, addr

    def handle_error(self, request, client_address) -> None:  # failed handshakes are routine
        pass


class NodeServer:
    """Serve an SRPProviderNode to exactly one authorised coordinator key."""

    def __init__(
        self,
        node: SRPProviderNode,
        coordinator_public_key_hex: str,
        host: str = "127.0.0.1",
        port: int = 0,
        ssl_context: Optional[ssl.SSLContext] = None,
        max_clock_skew_s: float = MAX_CLOCK_SKEW_S,
        connection_timeout_s: float = CONNECTION_TIMEOUT_S,
    ) -> None:
        self.node = node
        self.coordinator_key = coordinator_public_key_hex
        self.max_skew = max_clock_skew_s
        self._nonces = _NonceCache(max_clock_skew_s)
        self._methods: Dict[str, Callable[[Dict[str, Any]], Any]] = self._build_methods()
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            timeout = connection_timeout_s  # applied to the socket in setup()

            def setup(self) -> None:
                super().setup()  # sets the socket timeout first
                if isinstance(self.connection, ssl.SSLSocket):
                    self.connection.do_handshake()  # in this worker thread, under the timeout

            def log_message(self, *args: Any) -> None:  # keep stdout quiet
                pass

            def do_POST(self) -> None:  # noqa: N802
                status, body = server._handle(self)
                raw = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self._httpd = _TLSThreadingHTTPServer((host, port), Handler, ssl_context)
        self._httpd.daemon_threads = True
        self._scheme = "https" if ssl_context is not None else "http"
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"{self._scheme}://{host}:{port}{RPC_PATH}"

    def start(self) -> "NodeServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    # ---------------------------------------------------------------- serving
    def _signed(self, req_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, **payload,
                "sig": self.node._keypair.sign(_response_message(req_id, payload))}

    def _handle(self, handler: BaseHTTPRequestHandler) -> Tuple[int, Dict[str, Any]]:
        if handler.path != RPC_PATH:
            return 404, {"error": {"type": "KeyError", "message": "unknown path"}}
        try:
            length = int(handler.headers.get("Content-Length", "0"))
        except ValueError:
            return 400, {"error": {"type": "WireError", "message": "bad length"}}
        if not 0 < length <= MAX_FRAME_BYTES:
            return 413, {"error": {"type": "WireError", "message": "frame size"}}
        try:
            frame = loads_strict(handler.rfile.read(length))
            if not isinstance(frame, dict):
                raise WireError("frame must be an object")
            req_id, method, params, auth = frame.get("id"), frame.get("method"), frame.get("params"), frame.get("auth")
            if not isinstance(req_id, str) or not isinstance(method, str) or not isinstance(auth, dict):
                raise WireError("malformed envelope")
        except WireError as exc:
            return 400, {"error": {"type": "WireError", "message": str(exc)}}

        now = time.time()
        ts, nonce, sig = auth.get("ts"), auth.get("nonce"), auth.get("sig")
        if (
            auth.get("coordinator") != self.coordinator_key
            or not isinstance(ts, (int, float)) or not isinstance(nonce, str) or not isinstance(sig, str)
            or not verify_signature(
                self.coordinator_key,
                _command_message(self.node.node_id, method, params, req_id, ts, nonce),
                sig,
            )
        ):
            return 401, {"error": {"type": "PermissionError", "message": "unauthenticated command"}}
        if abs(now - float(ts)) > self.max_skew:
            return 401, {"error": {"type": "PermissionError", "message": "stale command (clock skew)"}}
        if not self._nonces.use(nonce, now):
            return 409, {"error": {"type": "PermissionError", "message": "replayed command"}}

        fn = self._methods.get(method)
        if fn is None:
            return 200, self._signed(req_id, {"error": {"type": "KeyError", "message": f"unknown method {method}"}})
        try:
            result = fn(params if isinstance(params, dict) else {})
            return 200, self._signed(req_id, {"result": result})
        except Exception as exc:
            etype = type(exc).__name__ if type(exc).__name__ in _ALLOWED_ERRORS else "RuntimeError"
            return 200, self._signed(req_id, {"error": {"type": etype, "message": str(exc)[:2000]}})

    def _build_methods(self) -> Dict[str, Callable[[Dict[str, Any]], Any]]:
        node = self.node

        def s(p: Dict[str, Any], key: str) -> str:
            v = p.get(key)
            if not isinstance(v, str):
                raise WireError(f"'{key}' must be a string")
            return v

        def fork(p: Dict[str, Any]) -> Dict[str, Any]:
            count = p.get("count")
            ids = p.get("branch_ids")
            ttl = p.get("ttl_seconds")
            if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 4096:
                raise WireError("'count' must be an integer in [0, 4096]")
            if ids is not None and (not isinstance(ids, list) or not all(isinstance(i, str) for i in ids)):
                raise WireError("'branch_ids' must be a list of strings")
            if ttl is not None and (isinstance(ttl, bool) or not isinstance(ttl, (int, float))):
                raise WireError("'ttl_seconds' must be a number")
            branches, ms = node.fork(s(p, "source_id"), count, ttl_seconds=ttl, branch_ids=ids)
            return {
                "fork_latency_ms": ms,
                "branches": [
                    {"branch_id": b.branch_id, "state_hash": b.state_hash, "root_snapshot_id": b.root_snapshot_id}
                    for b in branches
                ],
            }

        def step(p: Dict[str, Any]) -> Dict[str, Any]:
            action = decode_body(ActionPayload, p.get("action"))
            timeout = p.get("timeout_ms")
            if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 60_000:
                raise WireError("'timeout_ms' must be an integer in [1, 60000]")
            res = node.step(s(p, "branch_id"), action, request_id=s(p, "request_id"), timeout_ms=timeout)
            return dataclasses.asdict(res)

        def ping(p: Dict[str, Any]) -> Dict[str, Any]:
            return dataclasses.asdict(node.handle_memory_ping(decode_body(MemoryPingChallenge, p.get("challenge"))))

        def pin_ballast(p: Dict[str, Any]) -> Dict[str, Any]:
            count = p.get("page_count")
            if isinstance(count, bool) or not isinstance(count, int):
                raise WireError("'page_count' must be an integer")
            return {"bytes": node.pin_ballast_seed(s(p, "snapshot_id"), s(p, "seed_hex"), count)}

        return {
            "node.capabilities": lambda p: dataclasses.asdict(node.capabilities()),
            "node.prove_key_possession": lambda p: {"signature": node.prove_key_possession(s(p, "nonce"))},
            "node.pin_snapshot": lambda p: {
                "state_hash": node.pin_snapshot(decode_body(SnapshotManifest, p.get("manifest"))).state_hash
            },
            "node.pin_ballast_seed": pin_ballast,
            "node.ballast_page_count": lambda p: {"count": node.ballast_page_count(s(p, "snapshot_id"))},
            "node.evict_snapshot": lambda p: {
                "reclaimed": node.evict_snapshot(s(p, "snapshot_id"), bool(p.get("evict_branches", True)))
            },
            "node.fork": fork,
            "node.step": step,
            "node.evict_branch": lambda p: {"reclaimed": node.evict_branch(s(p, "branch_id"))},
            "node.reap_expired": lambda p: {"evicted": node.reap_expired()},
            "node.has_branch": lambda p: {"present": node.has_branch(s(p, "branch_id"))},
            "node.memory_ping": ping,
            "node.telemetry": lambda p: node.telemetry(),
        }


class RemoteNode:
    """
    Coordinator-side proxy for a NodeServer, signing every command with the
    coordinator's key and verifying every response with the node's key.
    Duck-types the SRPProviderNode surface the coordinator uses.
    """

    def __init__(
        self,
        url: str,
        coordinator_keypair: NodeKeypair,
        node_id: str,
        expected_public_key_hex: Optional[str] = None,
        timeout_s: float = 30.0,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.url = url
        self.node_id = node_id
        self._kp = coordinator_keypair
        self.timeout_s = timeout_s
        self._ssl = ssl_context
        self._node_key = expected_public_key_hex or ""
        caps = self.capabilities()
        if caps.node_id != node_id:
            raise PermissionError("Remote node reported a different node id")
        if expected_public_key_hex and caps.public_key_hex != expected_public_key_hex:
            raise PermissionError("Remote node presented an unexpected public key")
        self._node_key = caps.public_key_hex
        self.public_key_hex = caps.public_key_hex

    # ------------------------------------------------------------- plumbing
    def _call(self, method: str, params: Dict[str, Any]) -> Any:
        req_id = secrets.token_hex(12)
        ts, nonce = time.time(), secrets.token_hex(16)
        frame = {
            "jsonrpc": "2.0", "id": req_id, "method": method, "params": params,
            "auth": {"coordinator": self._kp.public_key_hex, "ts": ts, "nonce": nonce,
                     "sig": self._kp.sign(_command_message(self.node_id, method, params, req_id, ts, nonce))},
        }
        data = json.dumps(frame, allow_nan=False).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s, context=self._ssl) as resp:
                body = loads_strict(resp.read())
        except urllib.error.HTTPError as exc:
            raise PermissionError(f"Node rejected command ({exc.code})") from exc
        if not isinstance(body, dict) or body.get("id") != req_id:
            raise WireError("Response does not match request")
        payload = {k: body[k] for k in ("result", "error") if k in body}
        key = self._node_key
        if not key and method == "node.capabilities" and isinstance(payload.get("result"), dict):
            # Trust-on-first-use: the capabilities must be signed by the key they
            # announce; NODE_REGISTER's proof-of-possession then binds that key.
            key = str(payload["result"].get("public_key_hex", ""))
        if not key or not verify_signature(key, _response_message(req_id, payload), str(body.get("sig", ""))):
            raise PermissionError("Response signature invalid")
        if "error" in payload:
            err = payload["error"] if isinstance(payload["error"], dict) else {}
            raise _ALLOWED_ERRORS.get(str(err.get("type")), RuntimeError)(str(err.get("message", "")))
        return payload.get("result")

    # ------------------------------------------------------------- node API
    def capabilities(self) -> NodeCapabilities:
        return decode_body(NodeCapabilities, self._call("node.capabilities", {}))

    def prove_key_possession(self, nonce: str) -> str:
        return self._call("node.prove_key_possession", {"nonce": nonce})["signature"]

    def pin_snapshot(self, manifest: SnapshotManifest) -> SimpleNamespace:
        r = self._call("node.pin_snapshot", {"manifest": dataclasses.asdict(manifest)})
        return SimpleNamespace(snapshot_id=manifest.snapshot_id, state_hash=r["state_hash"])

    def pin_ballast_seed(self, snapshot_id: str, seed_hex: str, page_count: int) -> int:
        return int(self._call("node.pin_ballast_seed",
                              {"snapshot_id": snapshot_id, "seed_hex": seed_hex, "page_count": page_count})["bytes"])

    def ballast_page_count(self, snapshot_id: str) -> int:
        return int(self._call("node.ballast_page_count", {"snapshot_id": snapshot_id})["count"])

    def evict_snapshot(self, snapshot_id: str, evict_branches: bool = True) -> int:
        return int(self._call("node.evict_snapshot",
                              {"snapshot_id": snapshot_id, "evict_branches": evict_branches})["reclaimed"])

    def fork(self, source_id: str, count: int = 1, ttl_seconds: Optional[float] = None,
             branch_ids: Optional[List[str]] = None) -> Tuple[List[SimpleNamespace], float]:
        r = self._call("node.fork", {"source_id": source_id, "count": count,
                                     "ttl_seconds": ttl_seconds, "branch_ids": branch_ids})
        branches = [SimpleNamespace(**b) for b in r["branches"]]
        return branches, float(r["fork_latency_ms"])

    def step(self, branch_id: str, action: ActionPayload, request_id: Optional[str] = None,
             timeout_ms: int = 5000) -> StepResult:
        r = self._call("node.step", {"branch_id": branch_id, "request_id": request_id or secrets.token_hex(8),
                                     "timeout_ms": int(timeout_ms), "action": dataclasses.asdict(action)})
        return decode_body(StepResult, r)

    def evict_branch(self, branch_id: str) -> int:
        return int(self._call("node.evict_branch", {"branch_id": branch_id})["reclaimed"])

    def reap_expired(self) -> List[str]:
        return list(self._call("node.reap_expired", {})["evicted"])

    def has_branch(self, branch_id: str) -> bool:
        return bool(self._call("node.has_branch", {"branch_id": branch_id})["present"])

    def handle_memory_ping(self, challenge: MemoryPingChallenge) -> MemoryPingResponse:
        r = self._call("node.memory_ping", {"challenge": dataclasses.asdict(challenge)})
        return decode_body(MemoryPingResponse, r)

    def telemetry(self) -> Dict[str, Any]:
        return self._call("node.telemetry", {})
