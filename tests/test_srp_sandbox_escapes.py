"""
Sandbox escape-attempt suite (v0.7).

A catalogue of ways untrusted agent code might try to break out of the code
sandbox (`srp/envs/sandbox.py`) or fake a passing grade. Each case names the
mechanism it tries and the layer that is expected to stop it:

  policy   the static AST policy (`validate_code`) refuses the code.
  runtime  the code is accepted but fails at run time: the name does not exist
           in the restricted builtins, the audit hook refuses the operation,
           or a resource limit (fuel, recursion, sequence size) stops it.
  grading  the code runs, but cannot make a failing test pass or change what
           the tests see.

Kernel-level layers (seccomp, network namespace, rlimits) are covered by
`test_srp_security.py::test_S1_linux_kernel_layers_block_network_process_and_writes`
on Linux.

Two cases here were real findings when this suite was written (v0.7):
  * `str.isdigit = ...` in a solution changed the `str` class the pinned tests
    use, so a failing test could pass. Attribute assignment is now refused.
  * A format string assembled at run time (`('{0.' + '_' * 2 + ...).format(f)`)
    read private attributes, bypassing the static `__` checks. `.format` now
    requires a literal whose fields are checked.
"""

from __future__ import annotations

import pytest

from srp.envs import sandbox

PASSING_TEST = "def test_a():\n    pass\n"


def _run(solution: str, test: str = PASSING_TEST, names=("test_a",), **kw):
    return sandbox.run_test_job(solution, test, list(names), **kw)


# ------------------------------------------------------------------ policy
POLICY_CASES = [
    ("import statement", "import os\n"),
    ("from-import", "from os import system\n"),
    ("dunder import builtin", "m = __import__('os')\n"),
    ("subclass walk via dunder attributes", "x = ().__class__.__bases__[0].__subclasses__()\n"),
    ("function globals", "def f():\n    pass\ng = f.__globals__\n"),
    ("generator frame", "def g():\n    yield 1\nf = g().gi_frame\n"),
    ("traceback frame", "def f(e):\n    return e.tb_frame\n"),
    ("frame walk", "def f(fr):\n    return fr.f_back\n"),
    ("code object constants", "def f(c):\n    return c.co_consts\n"),
    ("class definition (custom __eq__ to fake asserts)", "class A:\n    pass\n"),
    ("dunder method definition", "def __eq__(a, b):\n    return True\n"),
    ("async machinery", "async def f():\n    pass\n"),
    ("global rebinding", "def f():\n    global x\n"),
    ("bare except (would swallow fuel exhaustion)", "try:\n    pass\nexcept:\n    pass\n"),
    ("dunder string constant", "k = '__class__'\n"),
    ("dunder lambda argument", "f = lambda __x: __x\n"),
    ("dunder keyword argument", "d = dict(__x=1)\n"),
    ("pattern-matching attribute read", "match 1:\n    case int(_private=y):\n        pass\n"),
    ("dunder pattern capture", "match 1:\n    case __x:\n        pass\n"),
    # Finding 1 (v0.7): shared replacement classes were writable.
    ("overwrite a str method the tests use", "str.isdigit = lambda s: True\n"),
    ("overwrite a set method the tests use", "set.issubset = lambda a, b: True\n"),
    ("overwrite a metered builtin's attribute", "sum.x = 1\n"),
    ("delete an attribute", "def f():\n    pass\ndel f.x\n"),
    ("augmented attribute assignment", "def f():\n    pass\nf.x += 1\n"),
    # Finding 2 (v0.7): run-time format strings could read private attributes.
    ("format string built at run time",
     "def f():\n    pass\ns = ('{0.' + '_' * 2 + 'globals' + '_' * 2 + '}').format(f)\n"),
    ("unbound str.format with a run-time string", "s = str.format('{0}', 1)\n"),
    ("format method alias", "g = '{}'.format\n"),
    ("format literal reading a private attribute", "s = '{0._x}'.format(1)\n"),
    ("format literal reading a frame attribute", "def g():\n    yield 1\ns = '{0.gi_frame}'.format(g())\n"),
    ("format literal with a nested spec reading a frame",
     "def g():\n    yield 1\ns = '{0:{1.gi_frame}}'.format(1, g())\n"),
    ("format_map literal reading a private attribute", "s = '{a._x}'.format_map({'a': 1})\n"),
]


@pytest.mark.parametrize("label,code", POLICY_CASES, ids=[c[0] for c in POLICY_CASES])
def test_policy_refuses(label, code):
    with pytest.raises(sandbox.SandboxPolicyError):
        sandbox.validate_code(code)


def test_policy_still_allows_ordinary_code():  # control: the policy is not simply refusing everything
    sandbox.validate_code(
        "def solve(xs):\n"
        "    seen = set()\n"
        "    out = []\n"
        "    for x in sorted(xs):\n"
        "        if x not in seen:\n"
        "            seen.add(x)\n"
        "            out.append(x)\n"
        "    label = '{0} items, first {1[0]}'.format(len(out), out)\n"
        "    return out, label, f'{len(out)}', '%d' % len(out)\n"
    )


# ----------------------------------------------------------------- runtime
MISSING_BUILTINS = [
    "open", "eval", "exec", "compile", "getattr", "setattr", "vars", "globals", "locals",
    "type", "id", "input", "breakpoint", "help", "memoryview", "object", "super", "exit",
]


@pytest.mark.parametrize("name", MISSING_BUILTINS)
def test_dangerous_builtins_do_not_exist(name):
    r = _run(f"x = {name}\n")
    assert r["error"] and r["error"].startswith("NameError"), r


def test_catching_exception_cannot_swallow_fuel_exhaustion():
    # FuelExhausted derives from BaseException, which agent code cannot name.
    code = (
        "def solve():\n"
        "    while True:\n"
        "        try:\n"
        "            while True:\n"
        "                pass\n"
        "        except Exception:\n"
        "            pass\n"
    )
    r = _run(code, "def test_a():\n    solve()\n", timeout_ms=300)
    assert r["passed"] == 0 and r["fuel_exhausted"] and not r["timed_out"], r


def test_unbounded_recursion_is_an_ordinary_failure():
    r = _run("def f(n):\n    return f(n + 1)\n", "def test_a():\n    f(0)\n")
    assert r["passed"] == 0 and "RecursionError" in r["failures"][0], r


def test_huge_sequence_allocation_is_refused():
    r = _run("x = [0] * (10 ** 10)\n")
    assert r["passed"] == 0 and r["error"], r


def test_output_flood_is_capped():
    r = _run("for i in range(200):\n    print('x' * 10000)\n")
    assert len(r["stdout"]) <= sandbox.MAX_STDOUT_CHARS and r["passed"] == 1, r


# ----------------------------------------------------------------- grading
def test_printed_fake_result_line_is_not_parsed():
    # The child reports results on a line prefixed with a per-job random nonce
    # that agent code never sees; printed text goes to a captured buffer.
    fake = 'print("SRPRES" + "0" * 32 + \'{"passed": 1, "total": 1}\')\n'
    r = _run(fake, "def test_a():\n    assert False\n")
    assert r["passed"] == 0 and r["total"] == 1, r


def test_solution_cannot_replace_a_test_function():
    r = _run("def test_a():\n    pass\n", "def test_a():\n    assert False\n")
    assert r["passed"] == 0, r


def test_solution_cannot_shadow_builtins_the_tests_use():
    r = _run("def len(x):\n    return 3\ndef solve():\n    return []\n",
             "def test_a():\n    assert len(solve()) == 3\n")
    assert r["passed"] == 0, r


def test_solution_cannot_fake_seeded_property_helpers():
    # srp_randint & co. are injected into the test namespace last.
    r = _run("def srp_randint(a, b):\n    return 0\ndef solve(n):\n    return 0\n",
             "def test_a():\n    n = srp_randint(1, 10 ** 9)\n    assert solve(n) == n\n",
             test_seed=1234)
    assert r["passed"] == 0, r


def test_solution_cannot_patch_the_str_class_seen_by_tests():
    # End-to-end form of finding 1: refused before anything runs.
    with pytest.raises(sandbox.SandboxPolicyError):
        _run("str.isdigit = lambda s: True\ndef solve():\n    return 'abc'\n",
             "def test_a():\n    assert str.isdigit(solve())\n")


def test_honest_solution_still_passes():  # control
    r = _run("def solve(xs):\n    return sorted(set(xs))\n",
             "def test_a():\n    assert solve([3, 1, 3, 2]) == [1, 2, 3]\n")
    assert r["passed"] == 1 and r["error"] is None, r
