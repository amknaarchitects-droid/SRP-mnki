"""
Benchmark 2: episode throughput and step latency under simulated network conditions.

Topology (all real TCP sockets on loopback, no mocks):

    SRPCoordinator -> RemoteNode --TCP--> DelayProxy --TCP--> NodeServer -> SRPProviderNode

The proxy is a delay line: every chunk is forwarded `rtt/2` after it arrived, in
each direction, optionally through a bandwidth cap. The proxy also holds each new
TCP connection for one extra round trip to stand in for the TCP handshake. SRP's
HTTP transport keeps connections alive, so that handshake is paid once per pooled
connection rather than once per command; the number of connections opened is
reported. TLS is not used here; a TLS handshake would add one or two further round
trips per new connection.

An episode is one SRP_FORK followed by the suite's steps, all through the proxy.
Each condition is run sequentially and with concurrent episodes, because waiting
on the network does not occupy the node.
"""

from __future__ import annotations

import argparse
import queue
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from benchmarks import common
from srp.node.daemon import SRPProviderNode
from srp.transport import NodeServer, RemoteNode

NAME = "network_simulation"

# time.sleep() on Windows before Python 3.11 rounds up to the ~15 ms timer tick.
_COARSE_SLEEP = sys.platform == "win32" and sys.version_info < (3, 11)


def _sleep_until(deadline: float) -> None:
    while True:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            return
        if _COARSE_SLEEP:
            time.sleep(remaining - 0.016 if remaining > 0.02 else 0)
        else:
            time.sleep(remaining)


class DelayProxy:
    """A TCP proxy that adds latency (and optionally a bandwidth cap) per direction."""

    def __init__(self, upstream: Tuple[str, int], rtt_ms: float,
                 bandwidth_mbit: Optional[float] = None, handshake_rtts: float = 1.0) -> None:
        self.upstream = upstream
        self.one_way_s = rtt_ms / 2000.0
        self.handshake_s = handshake_rtts * rtt_ms / 1000.0
        self.bytes_per_s = bandwidth_mbit * 1_000_000 / 8 if bandwidth_mbit else None
        self.bytes_to_node = 0
        self.bytes_from_node = 0
        self.connections = 0
        self._count_lock = threading.Lock()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(256)
        self.port = self._listener.getsockname()[1]
        self._closed = False
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def close(self) -> None:
        self._closed = True
        try:
            self._listener.close()
        except OSError:
            pass

    def _accept_loop(self) -> None:
        while not self._closed:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(client, time.perf_counter()), daemon=True).start()

    def _serve(self, client: socket.socket, accepted_at: float) -> None:
        try:
            _sleep_until(accepted_at + self.handshake_s)
            server = socket.create_connection(self.upstream)
        except OSError:
            client.close()
            return
        for sock in (client, server):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with self._count_lock:
            self.connections += 1
        self._pipe(client, server, "bytes_to_node")
        self._pipe(server, client, "bytes_from_node")

    def _pipe(self, src: socket.socket, dst: socket.socket, counter: str) -> None:
        pending: "queue.Queue[Optional[Tuple[float, bytes]]]" = queue.Queue()

        def reader() -> None:
            link_free_at = 0.0
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    now = time.perf_counter()
                    if self.bytes_per_s:
                        link_free_at = max(now, link_free_at) + len(data) / self.bytes_per_s
                        now = link_free_at
                    pending.put((now + self.one_way_s, data))
            except OSError:
                pass
            pending.put(None)

        def writer() -> None:
            try:
                while True:
                    item = pending.get()
                    if item is None:
                        break
                    deliver_at, data = item
                    _sleep_until(deliver_at)
                    dst.sendall(data)
                    with self._count_lock:
                        setattr(self, counter, getattr(self, counter) + len(data))
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        threading.Thread(target=reader, daemon=True).start()
        threading.Thread(target=writer, daemon=True).start()


def _run_condition(remote: RemoteNode, coord: Any, snapshot_id: str, actions: List[Any],
                   episodes: int, concurrency: int) -> Dict[str, Any]:
    step_ms: List[float] = []
    episode_ms: List[float] = []
    lock = threading.Lock()
    todo = list(range(episodes))
    errors: List[str] = []

    def worker() -> None:
        while True:
            with lock:
                if not todo:
                    return
                todo.pop()
            try:
                t_episode = time.perf_counter()
                bid = coord.fork(snapshot_id)[0][0]
                local: List[float] = []
                for action in actions:
                    t0 = time.perf_counter()
                    coord.step(bid, action)
                    local.append((time.perf_counter() - t0) * 1000.0)
                elapsed = (time.perf_counter() - t_episode) * 1000.0
                with lock:
                    step_ms.extend(local)
                    episode_ms.append(elapsed)
            except Exception as exc:  # recorded, never hidden
                with lock:
                    errors.append(f"{type(exc).__name__}: {exc}")

    t_start = time.perf_counter()
    threads = [threading.Thread(target=worker) for _ in range(concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall_s = time.perf_counter() - t_start
    return {
        "concurrency": concurrency,
        "episodes": len(episode_ms),
        "errors": errors[:3],
        "error_count": len(errors),
        "wall_s": round(wall_s, 3),
        "episodes_per_s": round(len(episode_ms) / wall_s, 3) if wall_s else None,
        "steps_per_s": round(len(step_ms) / wall_s, 3) if wall_s else None,
        "step": common.summarize(step_ms),
        "episode": common.summarize(episode_ms),
    }


def run(quick: bool = False, bandwidth_mbit: Optional[float] = None) -> Dict[str, Any]:
    rtts = [0, 20, 100] if quick else [0, 5, 20, 50, 100, 200]
    concurrencies = [1, 8] if quick else [1, 16]
    episodes = {"web": 6, "code": 3} if quick else {"web": 32, "code": 16}
    manifests = common.manifests()
    workloads: Dict[str, Any] = {}

    for key in ("web", "code"):
        manifest, actions = manifests[key], common.EPISODES[key]
        node = SRPProviderNode(node_id=f"net_{key}", ram_capacity_mb=512)
        coord = common.unaudited_coordinator()
        server = NodeServer(node, coord.keypair.public_key_hex).start()
        direct_url = server.url
        host, port = direct_url.split("//", 1)[1].split("/", 1)[0].rsplit(":", 1)
        remote = RemoteNode(direct_url, coord.keypair, node_id=node.node_id, timeout_s=120)
        coord.register_node(remote)
        coord.broadcast_snapshot(manifest)  # setup goes direct; only episodes are delayed

        conditions: List[Dict[str, Any]] = []
        for rtt in rtts:
            proxy = DelayProxy((host, int(port)), rtt, bandwidth_mbit) if rtt or bandwidth_mbit else None
            remote.url = direct_url.replace(f":{port}/", f":{proxy.port}/") if proxy else direct_url
            for conc in concurrencies:
                before = (proxy.bytes_to_node, proxy.bytes_from_node, proxy.connections) if proxy else None
                cond = _run_condition(remote, coord, manifest.snapshot_id, actions,
                                      max(episodes[key], conc), conc)
                cond["rtt_ms"] = rtt
                if proxy and before:
                    calls = max(1, cond["episodes"] * (1 + len(actions)))
                    cond["connections_opened"] = proxy.connections - before[2]
                    cond["bytes_per_call_to_node"] = round((proxy.bytes_to_node - before[0]) / calls)
                    cond["bytes_per_call_from_node"] = round((proxy.bytes_from_node - before[1]) / calls)
                conditions.append(cond)
            if proxy:
                proxy.close()
        remote.url = direct_url
        server.stop()

        local = [c for c in conditions if c["rtt_ms"] == 0]
        best_local = max(c["steps_per_s"] or 0.0 for c in local)
        local_p50 = min(c["step"]["p50_ms"] for c in local)
        for c in conditions:
            c["throughput_vs_best_local"] = round(c["steps_per_s"] / best_local, 4) if best_local else None
            c["added_step_p50_ms"] = round(c["step"]["p50_ms"] - local_p50, 3)
        workloads[key] = {
            "suite": manifest.suite,
            "calls_per_episode": 1 + len(actions),
            "conditions": conditions,
        }

    return {
        "benchmark": NAME,
        "quick": quick,
        "bandwidth_mbit": bandwidth_mbit,
        "handshake_round_trips_per_connection": 1.0,
        "persistent_connections": True,
        "tls": False,
        "workloads": workloads,
    }


def render(result: Dict[str, Any]) -> str:
    rows = [
        "| Suite | RTT ms | Concurrent episodes | Step p50 ms | Step p95 ms | Step p99 ms | Steps/s | vs best local |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for w in result["workloads"].values():
        for c in w["conditions"]:
            s = c["step"]
            ratio = f"{c['throughput_vs_best_local'] * 100:.1f}%" if c["throughput_vs_best_local"] is not None else "n/a"
            rows.append(
                f"| `{w['suite']}` | {c['rtt_ms']} | {c['concurrency']} | {common.fmt_ms(s.get('p50_ms'))} | "
                f"{common.fmt_ms(s.get('p95_ms'))} | {common.fmt_ms(s.get('p99_ms'))} | "
                f"{c['steps_per_s']:.1f} | {ratio} |"
            )
    return "\n".join(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--bandwidth-mbit", type=float, default=None,
                        help="cap each direction of the simulated link (default: uncapped)")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    result = run(args.quick, args.bandwidth_mbit)
    result["environment"] = common.environment()
    print(render(result))
    if args.out:
        print("wrote", common.write_json(args.out, NAME, result))


if __name__ == "__main__":
    main()
