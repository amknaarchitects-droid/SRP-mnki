"""
Regression tests for the v0.6 fixes the benchmarks pointed to
(see ROADMAP.md, "v0.6 fixes found by the benchmarks"):

1. Persistent HTTP connections in the transport.
2. A larger listen queue in NodeServer.
3. Pinned snapshots no longer retain the manifest (a second copy of every byte).

Each test except the controls failed before its fix.
"""

import gc
import http.client
import json
import threading
import time
import weakref

import pytest

from srp.cli import build_default_manifests
from srp.coordinator.server import SRPCoordinator
from srp.node.daemon import SRPProviderNode
from srp.protocol.messages import SnapshotManifest
from srp.transport import NodeServer, RemoteNode


def _served_node(node_id: str = "keepalive1"):
    coord = SRPCoordinator(canary_rate=0.0, audit_rate=0.0)
    node = SRPProviderNode(node_id=node_id, ram_capacity_mb=64)
    server = NodeServer(node, coord.keypair.public_key_hex).start()
    accepted = []
    original = server._httpd.get_request

    def counting_get_request():
        sock, addr = original()
        accepted.append(addr)
        return sock, addr

    server._httpd.get_request = counting_get_request
    return coord, node, server, accepted


# ---------------------------------------------------------------- fix 1
def test_remote_node_reuses_one_connection_for_sequential_calls():
    coord, node, server, accepted = _served_node()
    try:
        remote = RemoteNode(server.url, coord.keypair, node_id=node.node_id)
        for _ in range(20):
            remote.telemetry()
        assert len(accepted) == 1  # was 21: one TCP connection per call
    finally:
        server.stop()


def test_end_to_end_episode_over_keepalive_connections():
    coord, node, server, accepted = _served_node("keepalive2")
    try:
        coord.register_node(RemoteNode(server.url, coord.keypair, node_id=node.node_id))
        m = build_default_manifests()["math"]
        coord.broadcast_snapshot(m)
        bid = coord.fork(m.snapshot_id)[0][0]
        from srp.protocol.messages import ActionPayload
        coord.step(bid, ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"}))
        assert coord.step(bid, ActionPayload("apply_tactic", {"tactic": "omega"})).reward == 1.0
        assert len(accepted) <= 2
    finally:
        server.stop()


def test_stale_pooled_connection_is_retried_once_and_never_executes_twice():
    coord, node, server, accepted = _served_node("keepalive3")
    calls = []
    honest = node.has_branch

    def counted(branch_id):
        calls.append(branch_id)
        return honest(branch_id)

    node.has_branch = counted
    try:
        remote = RemoteNode(server.url, coord.keypair, node_id=node.node_id)
        remote.telemetry()
        server._httpd.close_open_connections()  # node drops the idle keep-alive connection
        time.sleep(0.05)
        assert remote.has_branch("nope") is False
        assert calls == ["nope"]
        assert len(accepted) == 2
    finally:
        server.stop()


def test_stopped_server_stops_serving_pooled_connections():
    coord, node, server, _ = _served_node("keepalive4")
    remote = RemoteNode(server.url, coord.keypair, node_id=node.node_id, timeout_s=5)
    remote.telemetry()
    server.stop()
    with pytest.raises(OSError):
        remote.telemetry()


def test_rejected_frames_close_the_connection():
    coord, node, server, _ = _served_node("keepalive5")
    try:
        host, port = server.url.split("//", 1)[1].split("/", 1)[0].rsplit(":", 1)
        conn = http.client.HTTPConnection(host, int(port), timeout=5)
        body = json.dumps({"jsonrpc": "2.0", "id": "x", "method": "node.telemetry", "params": {},
                           "auth": {"coordinator": "00", "ts": time.time(), "nonce": "n", "sig": "00"}})
        conn.request("POST", "/srp/v1", body=body, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 401
        assert resp.getheader("Connection") == "close"
        conn.close()
    finally:
        server.stop()


def test_changing_the_url_drops_pooled_connections():
    coord, node, server, accepted = _served_node("keepalive6")
    try:
        remote = RemoteNode(server.url, coord.keypair, node_id=node.node_id)
        remote.telemetry()
        remote.url = server.url  # e.g. pointing at a proxy and back
        remote.telemetry()
        assert len(accepted) == 2
    finally:
        server.stop()


# ---------------------------------------------------------------- fix 2
def test_node_server_listen_backlog_is_large():
    _, _, server, _ = _served_node("backlog1")
    try:
        assert server._httpd.request_queue_size >= 128  # socketserver default is 5
    finally:
        server.stop()


def test_concurrent_callers_all_succeed():  # control: correctness under concurrency
    coord, node, server, _ = _served_node("backlog2")
    try:
        remote = RemoteNode(server.url, coord.keypair, node_id=node.node_id)
        errors = []

        def worker():
            try:
                for _ in range(5):
                    remote.telemetry()
            except Exception as exc:  # pragma: no cover - reported below
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(32)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
    finally:
        server.stop()


# ---------------------------------------------------------------- fix 3
def test_pinned_snapshot_does_not_retain_the_manifest():
    node = SRPProviderNode(node_id="pin1", ram_capacity_mb=64)
    manifest = SnapshotManifest(
        snapshot_id="pin_release", suite="srp-env-code", runtime="wasm_cow",
        initial_files={"a.txt": "x" * 50_000, "b.txt": "y" * 9_000},
    )
    ref = weakref.ref(manifest)
    snap = node.pin_snapshot(manifest)
    del manifest
    gc.collect()
    assert ref() is None  # the arena must not keep the file contents twice
    assert not hasattr(snap, "manifest")

    branch = node.fork("pin_release", count=1)[0][0]
    assert branch.read_file("a.txt") == "x" * 50_000
    assert branch.read_file("b.txt") == "y" * 9_000
