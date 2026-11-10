"""
SRP v0.4.0 hardening tests: the residual risks closed after v0.3.0.

  * seccomp-BPF policy for x86_64 *and* aarch64, checked instruction by
    instruction with a small classic-BPF interpreter (runs on every OS);
  * hash-order determinism: sets can no longer hold identity-hashed values;
  * seeded property-based grading against over-fitting;
  * TLS / mTLS transport, and a stalled TLS client cannot block the server.
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import struct
import time

import pytest

from srp.coordinator.server import SRPCoordinator
from srp.envs import sandbox
from srp.envs.code_swe import PROPERTY_SALT_FILE, property_seed
from srp.node.daemon import SRPProviderNode
from srp.protocol.messages import ActionPayload, SnapshotManifest

DENY_MSG = "nondeterministic"


# ===================================================================== seccomp
def _run_bpf(prog, nr, arch, args=(0, 0, 0, 0, 0, 0)):
    """Evaluate a classic-BPF seccomp program against one `struct seccomp_data`."""
    data = struct.pack("<iIQ6Q", nr, arch, 0, *args)
    pc, acc, steps = 0, 0, 0
    while True:
        steps += 1
        assert steps < 10_000, "BPF program loops"
        code, jt, jf, k = prog[pc]
        if code == 0x20:  # BPF_LD | BPF_W | BPF_ABS
            acc = struct.unpack_from("<I", data, k)[0]
            pc += 1
        elif code == 0x15:  # JEQ
            pc += 1 + (jt if acc == k else jf)
        elif code == 0x35:  # JGE
            pc += 1 + (jt if acc >= k else jf)
        elif code == 0x45:  # JSET
            pc += 1 + (jt if acc & k else jf)
        elif code == 0x06:  # RET
            return k
        else:  # pragma: no cover
            raise AssertionError(f"unexpected BPF opcode {code:#x}")


ARCHES = {
    # arch: (audit arch, deny table, openat nr, allowed syscalls the interpreter needs)
    "x86_64": (sandbox.AUDIT_ARCH_X86_64, sandbox.SECCOMP_DENY_X86_64, 257,
               {"read": 0, "write": 1, "mmap": 9, "brk": 12, "futex": 202, "exit_group": 231}),
    "aarch64": (sandbox.AUDIT_ARCH_AARCH64, sandbox.SECCOMP_DENY_AARCH64, 56,
                {"read": 63, "write": 64, "mmap": 222, "brk": 214, "futex": 98, "exit_group": 94}),
}


@pytest.mark.parametrize("arch", sorted(ARCHES))
def test_seccomp_policy_semantics_per_architecture(arch):
    audit_arch, deny, openat, allowed = ARCHES[arch]
    prog = sandbox.seccomp_program(arch)
    assert len(prog) < 4096 and all(jt < 256 and jf < 256 for _, jt, jf, _ in prog)
    for nr in deny:
        assert _run_bpf(prog, nr, audit_arch) == sandbox.SECCOMP_RET_EPERM, deny[nr]
    for name, nr in allowed.items():
        assert nr not in deny
        assert _run_bpf(prog, nr, audit_arch) == sandbox.SECCOMP_RET_ALLOW, name
    # openat: read-only allowed, any write-capable flag refused
    assert _run_bpf(prog, openat, audit_arch, (0, 0, 0o0, 0, 0, 0)) == sandbox.SECCOMP_RET_ALLOW
    assert _run_bpf(prog, openat, audit_arch, (0, 0, 0o2000000, 0, 0, 0)) == sandbox.SECCOMP_RET_ALLOW  # O_CLOEXEC
    for flag in (0o1, 0o2, 0o100, 0o1000, 0o2000):
        assert _run_bpf(prog, openat, audit_arch, (0, 0, flag, 0, 0, 0)) == sandbox.SECCOMP_RET_EPERM
    # Any other ABI on the same kernel is killed outright.
    other = sandbox.AUDIT_ARCH_AARCH64 if arch == "x86_64" else sandbox.AUDIT_ARCH_X86_64
    assert _run_bpf(prog, allowed["read"], other) == sandbox.SECCOMP_RET_KILL
    assert _run_bpf(prog, allowed["read"], 0x40000028) == sandbox.SECCOMP_RET_KILL  # AUDIT_ARCH_ARM
    if arch == "x86_64":
        assert _run_bpf(prog, 0x40000000 | 41, audit_arch) == sandbox.SECCOMP_RET_KILL  # x32 socket


def test_seccomp_tables_cover_the_same_operations():
    x86 = set(sandbox.SECCOMP_DENY_X86_64.values())
    arm = set(sandbox.SECCOMP_DENY_AARCH64.values())
    # aarch64 only lacks the legacy calls the asm-generic table never had.
    legacy = {"open", "creat", "fork", "vfork", "rename", "mkdir", "rmdir", "link",
              "unlink", "symlink", "chmod", "chown", "lchown", "mknod"}
    assert arm <= x86
    assert x86 - arm <= legacy
    for critical in ("socket", "connect", "clone", "clone3", "execve", "ptrace", "unshare", "bpf"):
        assert critical in arm and critical in x86


def test_seccomp_arch_detection():
    assert sandbox.seccomp_arch("AMD64") == "x86_64"
    assert sandbox.seccomp_arch("x86_64") == "x86_64"
    assert sandbox.seccomp_arch("aarch64") == "aarch64"
    assert sandbox.seccomp_arch("arm64") == "aarch64"
    assert sandbox.seccomp_arch("riscv64") is None
    assert sandbox.seccomp_program_x86_64() == sandbox.seccomp_program("x86_64")


# ======================================================== hash-order determinism
def _run(sol: str, tests: str = "def test_a():\n    pass\n", **kw):
    names = [ln.split("(")[0][4:] for ln in tests.splitlines() if ln.startswith("def test_")]
    return sandbox.run_test_job(sol, tests, names, **kw)


@pytest.mark.parametrize(
    "code",
    [
        "def f():\n    return 1\ndef g():\n    return 2\nfs = {f, g}\n",
        "fs = set([len, abs])\n",
        "fs = frozenset([len])\n",
        "fs = {x for x in (len, abs)}\n",
        "s = {1, 2}\ns.add(len)\n",
        "s = set()\ns.update([abs])\n",
        "s = {1}\nt = s.union([len])\n",
        "s = frozenset([1])\nt = s.union([len])\n",
        "s = {1}\ns.symmetric_difference_update([len])\n",
        "d = {len: 1, abs: 2}\nks = d.keys() | set()\n",
        "d = {len: 1}\nks = set()\nks |= d.keys()\n",
        "d = {len: 1}\nholder = [set()]\nholder[0] |= d.keys()\n",
        "d = {len: 1}\nks = d.keys() & {len}\n",
        "s = {float('nan')}\n",
        "s = {(1, len)}\n",
        "s = {ValueError}\n",
        "s = {range}\n",
    ],
)
def test_sets_refuse_identity_hashed_values(code):
    res = _run(code)
    assert res["error"] is not None and DENY_MSG in res["error"], res


def test_deterministic_sets_keep_normal_semantics():
    sol = (
        "a = {3, 1, 2}\n"
        "b = set([2, 3, 4])\n"
        "c = a | b\n"
        "c.add(9)\n"
        "c -= {1}\n"
        "f = frozenset('ab')\n"
        "counts = {'x': 5}\n"
        "counts['x'] -= 2\n"
        "nested = [{1}]\n"
        "nested[0] |= {2}\n"
        "calls = []\n"
        "def key():\n"
        "    calls.append(1)\n"
        "    return 0\n"
        "arr = [10]\n"
        "arr[key()] -= 3\n"
        "n = 12\n"
        "n -= 2\n"
        "n |= 1\n"
        "print(sorted(c), sorted(a & b), sorted(a ^ b), sorted(f), counts['x'], nested, arr, len(calls), n)\n"
        "print(set(), frozenset(), {(1, 'a')}, frozenset([frozenset([1])]), {None} if False else 'ok')\n"
        "print(sorted({x % 3 for x in range(10)}), sorted(c.intersection([2, 3])), c.copy() == c)\n"
    )
    res = _run(sol)
    assert res["error"] is None, res
    assert res["stdout"].splitlines() == [
        "[2, 3, 4, 9] [2, 3] [1, 4] ['a', 'b'] 3 [{1, 2}] [7] 1 11",
        "set() frozenset() {(1, 'a')} frozenset({frozenset({1})}) ok",
        "[0, 1, 2] [2, 3] True",
    ]


def test_set_iteration_is_reproducible_across_runs():
    # Regression: `python -I` implies -E, which silently ignored PYTHONHASHSEED=0,
    # so string-set order changed on every run (and between node and auditor).
    sol = "s = {'kiwi', 'apple', 'fig', 'banana', 7, 3.5, (1, 2)}\nprint(list(s))\n"
    outs = {_run(sol)["stdout"] for _ in range(4)}
    assert len(outs) == 1


def test_planted_modules_in_cwd_are_not_imported(tmp_path, monkeypatch):
    for mod in ("json", "re", "builtins"):
        (tmp_path / f"{mod}.py").write_text("raise SystemExit('hijacked')\n")
    monkeypatch.chdir(tmp_path)
    res = _run("x = 1\n")
    assert res["error"] is None and res["passed"] == 1, res
    argv = sandbox.child_argv("pass")
    assert "-E" not in argv and "-I" not in argv and "-s" in argv and "-S" in argv


# ============================================================= property grading
PROPERTY_TESTS = (
    "def ref(xs):\n"
    "    out = []\n"
    "    for x in xs:\n"
    "        if x not in out:\n"
    "            out.append(x)\n"
    "    return out\n"
    "def test_visible():\n"
    "    assert dedupe([1, 1, 2]) == [1, 2]\n"
    "def test_property():\n"
    "    for _ in range(30):\n"
    "        xs = [srp_randint(0, 9) for _ in range(srp_randint(0, 12))]\n"
    "        assert dedupe(xs) == ref(xs), xs\n"
)
CORRECT = "def dedupe(xs):\n    seen = []\n    for x in xs:\n        if x not in seen:\n            seen.append(x)\n    return seen\n"
OVERFIT = "def dedupe(xs):\n    return [1, 2]\n"


def _prop_cluster(salt: str = "pepper", audit_rate: float = 1.0):
    coord = SRPCoordinator(canary_rate=0.0, audit_rate=audit_rate)
    node = SRPProviderNode(node_id="p1", ram_capacity_mb=64)
    coord.register_node(node)
    files = {"solution.py": "def dedupe(xs):\n    return xs\n", "test_suite.py": PROPERTY_TESTS}
    if salt is not None:
        files[PROPERTY_SALT_FILE] = salt
    m = SnapshotManifest(snapshot_id="snap_prop_" + str(salt), suite="srp-env-code",
                         runtime="wasm_cow", initial_files=files)
    coord.broadcast_snapshot(m)
    return coord, m


def test_property_tests_defeat_overfitting_and_replay_deterministically():
    coord, m = _prop_cluster()
    bid = coord.fork(m.snapshot_id)[0][0]
    over = coord.step(bid, ActionPayload("apply_patch", {"code": OVERFIT}))
    assert over.reward == 0.5 and "test_property" in over.observation.stderr
    good = coord.step(bid, ActionPayload("apply_patch", {"code": CORRECT}))
    assert good.reward == 1.0 and good.terminated
    assert coord.fraud_proofs == []  # every step was replay-audited (audit_rate=1.0)


def test_property_helpers_are_test_only_and_salt_is_hidden():
    coord, m = _prop_cluster()
    bid = coord.fork(m.snapshot_id)[0][0]
    peek = coord.step(bid, ActionPayload("read_file", {"path": PROPERTY_SALT_FILE}))
    assert peek.observation.exit_code == 1 and "pepper" not in peek.observation.stdout
    write = coord.step(bid, ActionPayload("apply_patch", {"path": PROPERTY_SALT_FILE, "code": "x = 1\n"}))
    assert "prohibited" in write.observation.stderr
    sneaky = "def dedupe(xs):\n    return [srp_randint(0, 1)]\n"
    res = coord.step(bid, ActionPayload("apply_patch", {"code": sneaky}))
    assert res.reward == 0.0 and "NameError" in res.observation.stderr


def test_property_seed_binds_salt_tests_and_submission():
    base = property_seed("t", "s", "solution.py", "c")
    assert base == property_seed("t", "s", "solution.py", "c")
    assert len({base, property_seed("t2", "s", "solution.py", "c"),
                property_seed("t", "s2", "solution.py", "c"),
                property_seed("t", "s", "other.py", "c"),
                property_seed("t", "s", "solution.py", "c2")}) == 5
    # length-prefixed: shifting bytes between fields changes the seed
    assert property_seed("ab", "c", "p", "x") != property_seed("a", "bc", "p", "x")


def test_seeded_rng_is_bit_exact():
    tests = "def test_a():\n    print([srp_randint(0, 1000) for _ in range(4)], srp_choice('xyz'), srp_random())\n"
    a = _run("", tests, test_seed=7)["stdout"]
    assert a == _run("", tests, test_seed=7)["stdout"]
    assert a != _run("", tests, test_seed=8)["stdout"]
    # splitmix64 reference values for seed 7 (independent of the host platform)
    def splitmix(seed):
        st, mask = seed, (1 << 64) - 1
        while True:
            st = (st + 0x9E3779B97F4A7C15) & mask
            z = ((st ^ (st >> 30)) * 0xBF58476D1CE4E5B9) & mask
            z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & mask
            yield z ^ (z >> 31)
    g = splitmix(7)
    span = 1001
    limit = (1 << 64) - ((1 << 64) % span)
    expect = []
    while len(expect) < 4:
        v = next(g)
        if v < limit:
            expect.append(v % span)
    assert a.startswith(str(expect))


# ===================================================================== TLS
def _make_pki(tmp_path):
    """A throwaway CA plus server and client leaf certificates."""
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)

    def write_key(key, name):
        path = tmp_path / name
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        return str(path)

    def write_cert(cert, name):
        path = tmp_path / name
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return str(path)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SRP test CA")])
    ca = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                     crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    def leaf(cn, eku, san):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        )
        if san is not None:
            builder = builder.add_extension(san, critical=False)
        return key, builder.sign(ca_key, hashes.SHA256())

    s_key, s_cert = leaf("127.0.0.1", ExtendedKeyUsageOID.SERVER_AUTH,
                         x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]))
    c_key, c_cert = leaf("coordinator", ExtendedKeyUsageOID.CLIENT_AUTH, None)
    return {
        "ca": write_cert(ca, "ca.pem"),
        "server_cert": write_cert(s_cert, "server.pem"), "server_key": write_key(s_key, "server.key"),
        "client_cert": write_cert(c_cert, "client.pem"), "client_key": write_key(c_key, "client.key"),
    }


def _server_ctx(pki, require_client_cert=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(pki["server_cert"], pki["server_key"])
    if require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(pki["ca"])
    return ctx


def _client_ctx(pki, with_cert=False):
    ctx = ssl.create_default_context(cafile=pki["ca"])
    if with_cert:
        ctx.load_cert_chain(pki["client_cert"], pki["client_key"])
    return ctx


def _remote_round_trip(coord, server, node_id, ctx):
    from srp.transport import RemoteNode

    from srp.cli import build_default_manifests

    coord.register_node(RemoteNode(server.url, coord.keypair, node_id=node_id, ssl_context=ctx, timeout_s=10))
    m = build_default_manifests()["math"]
    coord.broadcast_snapshot(m)
    bid = coord.fork(m.snapshot_id)[0][0]
    coord.step(bid, ActionPayload("apply_tactic", {"tactic": "rw [Nat.add_assoc]"}))
    assert coord.step(bid, ActionPayload("apply_tactic", {"tactic": "omega"})).reward == 1.0
    assert coord.verify_node_ram_residency(node_id, m.snapshot_id)[0] is True
    assert coord.fraud_proofs == []


def test_tls_transport_end_to_end_and_untrusted_clients_fail(tmp_path):
    from srp.transport import NodeServer, RemoteNode

    pki = _make_pki(tmp_path)
    coord = SRPCoordinator(canary_rate=0.0, audit_rate=1.0)
    node = SRPProviderNode(node_id="tls1", ram_capacity_mb=64)
    server = NodeServer(node, coord.keypair.public_key_hex, ssl_context=_server_ctx(pki)).start()
    try:
        assert server.url.startswith("https://")
        _remote_round_trip(coord, server, "tls1", _client_ctx(pki))
        # A client that does not trust the node's CA refuses to talk to it.
        with pytest.raises(Exception):
            RemoteNode(server.url, coord.keypair, node_id="tls1",
                       ssl_context=ssl.create_default_context(), timeout_s=5)
        # Plain HTTP against the TLS port fails.
        with pytest.raises(Exception):
            RemoteNode(server.url.replace("https://", "http://"), coord.keypair, node_id="tls1", timeout_s=5)
    finally:
        server.stop()


def test_mtls_requires_a_client_certificate(tmp_path):
    from srp.transport import NodeServer, RemoteNode

    pki = _make_pki(tmp_path)
    coord = SRPCoordinator(canary_rate=0.0, audit_rate=0.0)
    node = SRPProviderNode(node_id="mtls1", ram_capacity_mb=64)
    server = NodeServer(node, coord.keypair.public_key_hex,
                        ssl_context=_server_ctx(pki, require_client_cert=True)).start()
    try:
        with pytest.raises(Exception):
            RemoteNode(server.url, coord.keypair, node_id="mtls1", ssl_context=_client_ctx(pki), timeout_s=5)
        _remote_round_trip(coord, server, "mtls1", _client_ctx(pki, with_cert=True))
    finally:
        server.stop()


def test_stalled_tls_client_does_not_block_other_requests(tmp_path):
    from srp.transport import NodeServer, RemoteNode

    pki = _make_pki(tmp_path)
    coord = SRPCoordinator(canary_rate=0.0, audit_rate=0.0)
    node = SRPProviderNode(node_id="tls2", ram_capacity_mb=64)
    server = NodeServer(node, coord.keypair.public_key_hex, ssl_context=_server_ctx(pki),
                        connection_timeout_s=2.0).start()
    host, port = server._httpd.server_address[:2]
    stalled = [socket.create_connection((host, port)) for _ in range(3)]  # never send a ClientHello
    try:
        t0 = time.monotonic()
        remote = RemoteNode(server.url, coord.keypair, node_id="tls2", ssl_context=_client_ctx(pki), timeout_s=5)
        assert remote.telemetry() is not None
        assert time.monotonic() - t0 < 1.5  # served while the stalled handshakes are pending
    finally:
        for s in stalled:
            s.close()
        server.stop()
