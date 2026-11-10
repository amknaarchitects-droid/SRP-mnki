"""
SRP Isolated Code Sandbox
=========================
Agent-supplied code never executes inside the node daemon's process.

Layers of defence, applied on every grading run:

  1. Static AST policy (`validate_code`): no imports, async, class definitions,
     bare `except:`, `__dunder__` names/strings/definitions, `_private`
     attributes, or frame/code/traceback introspection attributes.
  2. Deterministic fuel metering (`srp.envs.fuel`): loops, calls,
     comprehensions, iteration-consuming builtins and big-integer/sequence
     arithmetic are charged against a budget derived from `timeout_ms`.
  3. Process isolation: a fresh `python -I -S` child with an empty environment,
     `PYTHONHASHSEED=0`, a minimal builtins dict, and job input on stdin.
  4. In-interpreter audit hook (all platforms): once armed, *every* CPython
     audit event is refused (imports, open, socket.*, subprocess, os.*,
     ctypes, sys._getframe, restricted attribute reads such as gi_frame /
     tb_frame / __code__, ...), except executing the two pre-compiled code
     objects. Audit hooks cannot be removed from Python code.
  5. OS isolation:
       Linux:   new user + network namespace (no interfaces at all), ASLR
                disabled (deterministic addresses), rlimits (address space,
                CPU, zero file size, no extra processes, few fds, no core),
                and a seccomp-BPF filter (x86_64) denying network, process
                creation, exec, ptrace, namespace/mount changes, kernel
                module/BPF/keyring calls and every write-capable open/rename/
                unlink/mkdir/chmod/truncate.
       Windows: the child starts *suspended*, joins a kill-on-close Job Object
                (per-process memory cap, CPU-time cap, single process), then
                resumes. Network is refused by layer 4 only.
  6. Determinism: memory addresses in any text crossing the boundary (print,
     str(), f-strings, %-formatting, .format(), error messages) are scrubbed
     to `0x?`, and the pinned tests run in their own namespace so a solution
     cannot shadow builtins the tests rely on.

`isolation_report()` states which OS layers are active on this host. Nodes
advertise it, and coordinators may require kernel-level isolation.
"""

from __future__ import annotations

import ast
import json
import os
import platform
import secrets
import subprocess
import sys
from typing import Any, Dict, List, Optional

from srp.envs import fuel

MAX_CODE_CHARS = 200_000
MAX_AST_NODES = 50_000
MAX_STDOUT_CHARS = 65_536
DEFAULT_MEMORY_MB = 256
MIN_TIMEOUT_MS = 100
MAX_TIMEOUT_MS = 30_000

SAFE_BUILTIN_NAMES = (
    "abs", "all", "any", "bin", "bool", "chr", "dict", "divmod", "enumerate",
    "filter", "float", "frozenset", "hex", "int", "isinstance", "len", "list",
    "map", "max", "min", "oct", "ord", "pow", "range", "reversed", "round",
    "set", "slice", "sorted", "str", "sum", "tuple", "zip",
    "ValueError", "TypeError", "KeyError", "IndexError", "AssertionError",
    "ZeroDivisionError", "StopIteration", "ArithmeticError", "LookupError",
    "RuntimeError", "OverflowError", "MemoryError", "RecursionError", "Exception",
    "True", "False", "None",
)

FORBIDDEN_ATTRS = frozenset(
    {
        "gi_frame", "gi_code", "gi_yieldfrom", "gi_running",
        "cr_frame", "cr_code", "cr_await", "cr_origin",
        "ag_frame", "ag_code", "ag_await",
        "f_back", "f_globals", "f_locals", "f_builtins", "f_code", "f_trace", "f_lasti",
        "tb_frame", "tb_next", "tb_lasti", "tb_lineno",
        "co_code", "co_consts", "co_names",
        "func_globals", "func_code", "im_func", "im_self",
        "mro", "with_traceback",
    }
)


class SandboxPolicyError(PermissionError):
    """Raised when code violates the static sandbox policy."""


def validate_code(code: str) -> ast.Module:
    """Parse and enforce the static sandbox policy; returns the AST."""
    if len(code) > MAX_CODE_CHARS:
        raise SandboxPolicyError(f"Code exceeds {MAX_CODE_CHARS} characters")
    tree = ast.parse(code)
    count = 0
    for node in ast.walk(tree):
        count += 1
        if count > MAX_AST_NODES:
            raise SandboxPolicyError(f"Code exceeds {MAX_AST_NODES} AST nodes")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise SandboxPolicyError("Import statements are blocked in the sandbox")
        if isinstance(node, (ast.AsyncFunctionDef, ast.Await, ast.AsyncFor, ast.AsyncWith)):
            raise SandboxPolicyError("Async constructs are blocked in the sandbox")
        if isinstance(node, ast.ClassDef):
            raise SandboxPolicyError("Class definitions are blocked in the sandbox")
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            raise SandboxPolicyError("global/nonlocal declarations are blocked in the sandbox")
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            raise SandboxPolicyError("Bare 'except:' is blocked (use 'except Exception:')")
        if isinstance(node, ast.Name) and node.id.startswith("__"):
            raise SandboxPolicyError(f"Dunder name '{node.id}' is blocked in sandbox")
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("_"):
                raise SandboxPolicyError(f"Private/dunder attribute '{node.attr}' is blocked")
            if node.attr in FORBIDDEN_ATTRS:
                raise SandboxPolicyError(f"Introspection attribute '{node.attr}' is blocked")
        if isinstance(node, (ast.FunctionDef, ast.Lambda)) and getattr(node, "name", "").startswith("__"):
            raise SandboxPolicyError(f"Dunder definition '{node.name}' is blocked")
        if isinstance(node, ast.arg) and node.arg.startswith("__"):
            raise SandboxPolicyError(f"Dunder argument '{node.arg}' is blocked")
        if isinstance(node, ast.keyword) and node.arg and node.arg.startswith("__"):
            raise SandboxPolicyError(f"Dunder keyword '{node.arg}' is blocked")
        if isinstance(node, ast.alias) and node.name.startswith("__"):
            raise SandboxPolicyError("Dunder alias is blocked")
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            text = node.value if isinstance(node.value, str) else node.value.decode("latin-1")
            if "__" in text:
                raise SandboxPolicyError("String constants containing '__' are blocked")
    return tree


# --------------------------------------------------------------------------- #
# Text scrubbing instrumentation (runs after validation)                       #
# --------------------------------------------------------------------------- #
_SCRUB = "__srp_scrub__"


class _ScrubInstrumenter(ast.NodeTransformer):
    """Route f-strings, %-formatting and .format()/.format_map() through the scrubber."""

    def visit_JoinedStr(self, node: ast.JoinedStr):
        self.generic_visit(node)
        return ast.copy_location(
            ast.Call(func=ast.Name(id=_SCRUB, ctx=ast.Load()), args=[node], keywords=[]), node
        )

    def visit_BinOp(self, node: ast.BinOp):
        self.generic_visit(node)
        if isinstance(node.op, ast.Mod):
            return ast.copy_location(
                ast.Call(func=ast.Name(id=_SCRUB, ctx=ast.Load()), args=[node], keywords=[]), node
            )
        return node

    def visit_Call(self, node: ast.Call):
        self.generic_visit(node)
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("format", "format_map"):
            return ast.copy_location(
                ast.Call(func=ast.Name(id=_SCRUB, ctx=ast.Load()), args=[node], keywords=[]), node
            )
        return node


def prepare_source(tree: ast.Module) -> str:
    """Instrument a validated AST (scrubbing, then fuel) and return source text."""
    tree = _ScrubInstrumenter().visit(tree)
    ast.fix_missing_locations(tree)
    return fuel.instrument(tree)


# --------------------------------------------------------------------------- #
# Linux seccomp-BPF policy (x86_64)                                            #
# --------------------------------------------------------------------------- #
# Denied with EPERM. Everything else (read/write on existing fds, mmap/brk,
# futex, exit_group, clock, ...) is allowed so the interpreter can run.
SECCOMP_DENY_X86_64 = {
    # network
    41: "socket", 42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom",
    46: "sendmsg", 47: "recvmsg", 48: "shutdown", 49: "bind", 50: "listen",
    53: "socketpair", 54: "setsockopt", 288: "accept4", 299: "recvmmsg", 307: "sendmmsg",
    # process creation / exec / tracing
    56: "clone", 57: "fork", 58: "vfork", 59: "execve", 322: "execveat", 435: "clone3",
    62: "kill", 101: "ptrace", 310: "process_vm_readv", 311: "process_vm_writev",
    # filesystem mutation
    2: "open", 85: "creat", 437: "openat2", 76: "truncate", 77: "ftruncate",
    82: "rename", 264: "renameat", 316: "renameat2", 83: "mkdir", 258: "mkdirat",
    84: "rmdir", 86: "link", 265: "linkat", 87: "unlink", 263: "unlinkat",
    88: "symlink", 266: "symlinkat", 90: "chmod", 91: "fchmod", 268: "fchmodat",
    92: "chown", 93: "fchown", 94: "lchown", 260: "fchownat", 133: "mknod", 259: "mknodat",
    # namespaces, mounts, kernel attack surface
    165: "mount", 166: "umount2", 272: "unshare", 308: "setns", 155: "pivot_root",
    161: "chroot", 169: "reboot", 175: "init_module", 313: "finit_module",
    176: "delete_module", 246: "kexec_load", 320: "kexec_file_load", 321: "bpf",
    298: "perf_event_open", 248: "add_key", 249: "request_key", 250: "keyctl",
    425: "io_uring_setup", 426: "io_uring_enter", 427: "io_uring_register",
    135: "personality", 319: "memfd_create", 323: "userfaultfd",
}
SECCOMP_OPENAT_X86_64 = 257
OPEN_WRITE_FLAGS = 0o1 | 0o2 | 0o100 | 0o1000 | 0o2000  # WRONLY|RDWR|CREAT|TRUNC|APPEND


def seccomp_program_x86_64() -> List[tuple]:
    """BPF instructions (code, jt, jf, k) implementing the deny policy."""
    LD_W_ABS, JEQ, JGE, JSET, RET = 0x20, 0x15, 0x35, 0x45, 0x06
    KILL, ALLOW, EPERM = 0x80000000, 0x7FFF0000, 0x00050000 | 1
    AUDIT_ARCH_X86_64 = 0xC000003E
    prog = [
        (LD_W_ABS, 0, 0, 4),
        (JEQ, 1, 0, AUDIT_ARCH_X86_64),
        (RET, 0, 0, KILL),
        (LD_W_ABS, 0, 0, 0),
        (JGE, 0, 1, 0x40000000),  # x32 ABI
        (RET, 0, 0, KILL),
    ]
    for nr in sorted(SECCOMP_DENY_X86_64):
        prog += [(JEQ, 0, 1, nr), (RET, 0, 0, EPERM)]
    prog += [
        (JEQ, 0, 3, SECCOMP_OPENAT_X86_64),
        (LD_W_ABS, 0, 0, 16 + 8 * 2),  # low 32 bits of args[2] (flags)
        (JSET, 0, 1, OPEN_WRITE_FLAGS),
        (RET, 0, 0, EPERM),
        (RET, 0, 0, ALLOW),
    ]
    return prog


def isolation_report() -> Dict[str, Any]:
    """Describe the OS isolation layers this host can apply to the sandbox child."""
    system = platform.system()
    report: Dict[str, Any] = {
        "platform": system.lower(),
        "audit_hook": True,
        "fuel_metering": True,
        "process_isolation": True,
        "memory_cap": True,
        "cpu_cap": True,
        "network_namespace": False,
        "seccomp": False,
        "aslr_disabled": False,
        "kernel_network_isolation": False,
    }
    if system == "Linux":
        report["seccomp"] = platform.machine() in ("x86_64", "AMD64")
        report["network_namespace"] = _probe_unshare()
        report["aslr_disabled"] = True
        report["kernel_network_isolation"] = bool(report["network_namespace"] or report["seccomp"])
    return report


_UNSHARE_OK: Optional[bool] = None


def _probe_unshare() -> bool:  # pragma: no cover - Linux only
    global _UNSHARE_OK
    if _UNSHARE_OK is None:
        try:
            r = subprocess.run(
                [sys.executable, "-I", "-S", "-c", "pass"],
                preexec_fn=_linux_preexec(64, 2, probe=True),
                capture_output=True,
                timeout=10,
            )
            _UNSHARE_OK = r.returncode == 0
        except Exception:
            _UNSHARE_OK = False
    return _UNSHARE_OK


# --------------------------------------------------------------------------- #
# Child interpreter program                                                    #
# --------------------------------------------------------------------------- #
_CHILD_PROGRAM = r'''
import sys, json, re, builtins as _b
_ADDR = re.compile(r"0x[0-9a-fA-F]{4,}")
def _scrub_text(s):
    return _ADDR.sub("0x?", s) if isinstance(s, str) else s

''' + fuel.RUNTIME_SOURCE + r'''

def _apply_seccomp(prog):
    import ctypes
    class sock_filter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                    ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
    class sock_fprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(sock_filter))]
    arr = (sock_filter * len(prog))(*[sock_filter(*ins) for ins in prog])
    fprog = sock_fprog(len(prog), ctypes.cast(arr, ctypes.POINTER(sock_filter)))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:          # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    if libc.prctl(22, 2, ctypes.byref(fprog), 0, 0) != 0:   # PR_SET_SECCOMP, FILTER
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP failed")

def _run():
    job = json.loads(sys.stdin.readline())
    nonce = job["nonce"]; cap = job["max_stdout"]
    out = []; size = [0]
    def _print(*args, sep=" ", end="\n", **_kw):
        if size[0] >= cap:
            return
        text = _scrub_text(str(sep).join(_real_str(a) for a in args) + str(end))
        text = text[: cap - size[0]]
        out.append(text); size[0] += len(text)
    _real_str = str

    class _StrMeta(type):
        def __instancecheck__(cls, obj):
            return isinstance(obj, _real_str)
        def __subclasscheck__(cls, sub):
            return issubclass(sub, _real_str)
    class _ScrubbedStr(_real_str, metaclass=_StrMeta):
        def __new__(cls, *args, **kwargs):
            return _scrub_text(_real_str(*args, **kwargs))

    def make_builtins():
        safe = {}
        for name in job["builtins"]:
            if hasattr(_b, name):
                safe[name] = getattr(_b, name)
        safe["str"] = _ScrubbedStr
        safe["print"] = _print
        return safe

    sol_safe = make_builtins()
    sol_hooks, fuel_state = _make_fuel(job["fuel"], sol_safe, job["max_int_bits"], job["max_seq_items"])
    test_safe = make_builtins()
    test_hooks, _ = _make_fuel(job["fuel"], test_safe, job["max_int_bits"], job["max_seq_items"])
    # One shared budget for solution + tests
    test_hooks.update({k: v for k, v in sol_hooks.items()})
    for k in ("sum", "sorted", "list", "tuple", "set", "frozenset", "min", "max", "any", "all", "pow"):
        if k in sol_safe:
            test_safe[k] = sol_safe[k]

    res = {"passed": 0, "total": 0, "failures": [], "error": None,
           "fuel_used": 0, "fuel_limit": job["fuel"], "fuel_exhausted": False}
    try:
        sol_code = compile(job["solution"], job["solution_path"], "exec")
        test_code = compile(job["test_code"], job["test_path"], "exec")
    except SyntaxError as e:
        res["error"] = "SyntaxError: " + str(e)
        sys.__stdout__.write(nonce + json.dumps(res) + "\n"); sys.__stdout__.flush()
        return
    if job.get("seccomp_prog"):
        _apply_seccomp([tuple(i) for i in job["seccomp_prog"]])

    armed = [False]
    def _hook(event, args):
        if not armed[0]:
            return
        if event == "exec" and args and (args[0] is sol_code or args[0] is test_code):
            return
        raise RuntimeError("sandbox: operation '%s' is not permitted" % event)
    sys.addaudithook(_hook)
    sys.setrecursionlimit(job["recursion_limit"])

    sol_ns = {"__builtins__": sol_safe, "__srp_scrub__": _scrub_text}
    sol_ns.update(sol_hooks)
    armed[0] = True
    try:
        exec(sol_code, sol_ns)
        # Tests see only the solution's public, non-builtin symbols, resolved in a
        # clean namespace: a solution cannot shadow builtins the tests call.
        test_ns = {"__builtins__": test_safe, "__srp_scrub__": _scrub_text}
        test_ns.update(test_hooks)
        for k, v in sol_ns.items():
            if not k.startswith("_") and k not in test_safe and k not in job["tests"]:
                test_ns[k] = v
        exec(test_code, test_ns)
        funcs = [(n, test_ns[n]) for n in job["tests"] if n in test_ns and callable(test_ns[n])]
        res["total"] = len(funcs)
        for n, fn in funcs:
            try:
                fn(); res["passed"] += 1
            except FuelExhausted as e:
                res["fuel_exhausted"] = True
                res["failures"].append(n + ": FuelExhausted")
            except BaseException as e:
                res["failures"].append(n + ": " + type(e).__name__ + ": " + _scrub_text(_real_str(e))[:500])
    except FuelExhausted:
        res["fuel_exhausted"] = True
        res["error"] = "FuelExhausted: deterministic instruction budget exceeded"
    except BaseException as e:
        res["error"] = type(e).__name__ + ": " + _scrub_text(_real_str(e))[:2000]
    res["fuel_used"] = min(fuel_state[0], job["fuel"])
    res["stdout"] = "".join(out)
    sys.__stdout__.write(nonce + json.dumps(res) + "\n")
    sys.__stdout__.flush()
_run()
'''


def _linux_preexec(memory_mb: int, cpu_seconds: int, probe: bool = False):  # pragma: no cover
    def _apply() -> None:
        import ctypes
        import resource

        libc = ctypes.CDLL(None, use_errno=True)
        CLONE_NEWUSER, CLONE_NEWNET = 0x10000000, 0x40000000
        if libc.unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0 and probe:
            raise OSError(ctypes.get_errno(), "unshare failed")
        libc.personality(0x0040000)  # ADDR_NO_RANDOMIZE: deterministic addresses
        mem = memory_mb * 1024 * 1024
        for res, val in (
            (resource.RLIMIT_AS, mem),
            (resource.RLIMIT_CPU, cpu_seconds),
            (resource.RLIMIT_FSIZE, 0),  # zero-disk-wear: no file writes at all
            (resource.RLIMIT_NOFILE, 16),
            (resource.RLIMIT_CORE, 0),
            (resource.RLIMIT_NPROC, 0),
        ):
            try:
                resource.setrlimit(res, (val, val))
            except (ValueError, OSError):
                pass

    return _apply


def _posix_preexec(memory_mb: int, cpu_seconds: int):  # pragma: no cover - non-Linux POSIX
    def _apply() -> None:
        import resource

        mem = memory_mb * 1024 * 1024
        for res, val in (
            (resource.RLIMIT_AS, mem),
            (resource.RLIMIT_CPU, cpu_seconds),
            (resource.RLIMIT_FSIZE, 0),
            (resource.RLIMIT_NOFILE, 16),
            (resource.RLIMIT_CORE, 0),
        ):
            try:
                resource.setrlimit(res, (val, val))
            except (ValueError, OSError):
                pass

    return _apply


class _WindowsJob:  # pragma: no cover - Windows only
    """Kill-on-close Job: per-process memory cap, CPU-time cap, single process."""

    def __init__(self, memory_mb: int, cpu_seconds: int) -> None:
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._k32 = k32
        self._ntdll = ctypes.WinDLL("ntdll")

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class BASIC(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class EXTENDED(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BASIC),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        k32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]

        self.handle = k32.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
        info = EXTENDED()
        JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
        JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_PROCESS_TIME
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        info.BasicLimitInformation.PerProcessUserTimeLimit = int(cpu_seconds * 10_000_000)
        info.BasicLimitInformation.ActiveProcessLimit = 1
        info.ProcessMemoryLimit = memory_mb * 1024 * 1024
        if not k32.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            err = ctypes.get_last_error()
            k32.CloseHandle(self.handle)
            raise OSError(err, "SetInformationJobObject failed")

    def assign_and_resume(self, proc: subprocess.Popen) -> None:
        handle = int(proc._handle)
        if not self._k32.AssignProcessToJobObject(self.handle, handle):
            raise OSError(self._ctypes.get_last_error(), "AssignProcessToJobObject failed")
        if self._ntdll.NtResumeProcess(handle) != 0:
            raise OSError("NtResumeProcess failed")

    def close(self) -> None:
        if self.handle:
            self._k32.CloseHandle(self.handle)
            self.handle = None


def _child_env() -> Dict[str, str]:
    env = {"PYTHONHASHSEED": "0", "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
    if os.name == "nt":
        for key in ("SYSTEMROOT", "SystemRoot"):
            if key in os.environ:
                env["SYSTEMROOT"] = os.environ[key]
                break
    return env


def backstop_ms(timeout_ms: int) -> int:
    """Wall-clock backstop: generous, because fuel is the deterministic limit."""
    return 2 * int(timeout_ms) + 1000


def run_test_job(
    solution_code: str,
    test_code: str,
    test_names: List[str],
    solution_path: str = "solution.py",
    test_path: str = "test_suite.py",
    timeout_ms: int = 5000,
    memory_mb: int = DEFAULT_MEMORY_MB,
    recursion_limit: int = 1000,
) -> Dict[str, Any]:
    """
    Run `solution_code` then the pinned `test_code` in an isolated child.
    Both sources must already have passed `validate_code`; instrumentation is
    applied here. Returns {"passed", "total", "failures", "stdout", "error",
    "timed_out", "fuel_used", "fuel_limit", "fuel_exhausted"}.
    """
    timeout_ms = int(max(MIN_TIMEOUT_MS, min(int(timeout_ms), MAX_TIMEOUT_MS)))
    nonce = "SRPRES" + secrets.token_hex(16)
    fuel_limit = fuel.fuel_for_timeout(timeout_ms)
    deadline_ms = backstop_ms(timeout_ms)
    cpu_seconds = max(1, -(-deadline_ms // 1000) + 1)
    is_linux = platform.system() == "Linux"
    use_seccomp = is_linux and platform.machine() in ("x86_64", "AMD64")

    job = json.dumps(
        {
            "nonce": nonce,
            "max_stdout": MAX_STDOUT_CHARS,
            "builtins": list(SAFE_BUILTIN_NAMES),
            "solution": prepare_source(validate_code(solution_code)),
            "solution_path": solution_path,
            "test_code": prepare_source(validate_code(test_code)),
            "test_path": test_path,
            "tests": list(test_names),
            "fuel": fuel_limit,
            "max_int_bits": fuel.MAX_INT_BITS,
            "max_seq_items": fuel.MAX_SEQ_ITEMS,
            "recursion_limit": int(recursion_limit),
            "seccomp_prog": seccomp_program_x86_64() if use_seccomp else None,
        }
    )

    popen_kwargs: Dict[str, Any] = dict(
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_child_env()
    )
    win_job: Optional[_WindowsJob] = None
    if os.name == "nt":  # pragma: no cover - platform specific
        CREATE_SUSPENDED = 0x00000004
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0) | CREATE_SUSPENDED
        win_job = _WindowsJob(memory_mb, cpu_seconds)
    elif is_linux:  # pragma: no cover - platform specific
        popen_kwargs["preexec_fn"] = _linux_preexec(memory_mb, cpu_seconds)
        popen_kwargs["start_new_session"] = True
    else:  # pragma: no cover - platform specific
        popen_kwargs["preexec_fn"] = _posix_preexec(memory_mb, cpu_seconds)
        popen_kwargs["start_new_session"] = True

    timed_out = False
    try:
        proc = subprocess.Popen([sys.executable, "-I", "-S", "-c", _CHILD_PROGRAM], **popen_kwargs)
        try:
            if win_job is not None:
                win_job.assign_and_resume(proc)  # nothing runs before the Job applies
            stdout, stderr = proc.communicate(job.encode("utf-8") + b"\n", timeout=deadline_ms / 1000.0)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            stdout, stderr = proc.communicate()
        except BaseException:
            proc.kill()
            proc.communicate()
            raise
    finally:
        if win_job is not None:
            win_job.close()

    base: Dict[str, Any] = {
        "passed": 0, "total": 0, "failures": [], "stdout": "", "error": None,
        "timed_out": timed_out, "fuel_used": 0, "fuel_limit": fuel_limit, "fuel_exhausted": False,
    }
    if timed_out:
        # Deliberately free of wall-clock numbers: this text enters hashed state.
        base["error"] = "TimeoutError: wall-clock backstop exceeded"
        return base

    text = stdout.decode("utf-8", errors="replace")
    for line in reversed(text.splitlines()):
        if line.startswith(nonce):
            try:
                parsed = json.loads(line[len(nonce):])
            except ValueError:
                break
            base.update(
                passed=int(parsed.get("passed", 0)),
                total=int(parsed.get("total", 0)),
                failures=[str(f) for f in parsed.get("failures", [])][:100],
                stdout=str(parsed.get("stdout", ""))[:MAX_STDOUT_CHARS],
                error=parsed.get("error"),
                fuel_used=int(parsed.get("fuel_used", 0)),
                fuel_exhausted=bool(parsed.get("fuel_exhausted", False)),
            )
            return base

    # No well-formed result: killed by a resource limit or crashed. Exit codes
    # are platform-specific, so the hashed text stays generic.
    base["error"] = "SandboxError: child terminated by a resource limit"
    return base
