"""
SRP Flagship Verifier Suite 1: `srp-env-code` (Code & SWE Unit-Test Verifier)
=============================================================================
Executes code patches and unit assertions strictly in-memory against a
Copy-on-Write (CoW) branch without touching the host filesystem.
"""

from __future__ import annotations

import ast
import io
import contextlib
from typing import Any, Dict, Tuple

from srp.node.ram_arena import CoWBranch
from srp.protocol.messages import ActionPayload, StepObservation

SAFE_BUILTINS = {
    "abs": abs,
    "all": all,
    "any": any,
    "bin": bin,
    "bool": bool,
    "chr": chr,
    "dict": dict,
    "divmod": divmod,
    "enumerate": enumerate,
    "filter": filter,
    "float": float,
    "hex": hex,
    "int": int,
    "isinstance": isinstance,
    "len": len,
    "list": list,
    "map": map,
    "max": max,
    "min": min,
    "ord": ord,
    "pow": pow,
    "print": print,
    "range": range,
    "reversed": reversed,
    "round": round,
    "set": set,
    "slice": slice,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "zip": zip,
    "ValueError": ValueError,
    "TypeError": TypeError,
    "KeyError": KeyError,
    "IndexError": IndexError,
    "AssertionError": AssertionError,
    "Exception": Exception,
}

FORBIDDEN_AST_NODES = (ast.Import, ast.ImportFrom)


def _validate_ast_safety(code_str: str) -> None:
    tree = ast.parse(code_str)
    for node in ast.walk(tree):
        if isinstance(node, FORBIDDEN_AST_NODES):
            raise PermissionError("Import statements are blocked in Tier-1 in-memory code sandbox")
        if isinstance(node, ast.Name) and node.id.startswith("__"):
            raise PermissionError(f"Dunder attribute access '{node.id}' is blocked in sandbox")
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            raise PermissionError(f"Dunder attribute '{node.attr}' is blocked in sandbox")


class CodeSWEVerifier:
    """
    In-memory SWE / Code RL environment verifier.
    Supports commands:
      - `apply_patch`: writes updated source code to `solution.py` (or target file) in CoW RAM
        and immediately runs the pinned `test_suite.py` assertions.
      - `read_file`: reads a file from the CoW branch.
    """

    suite_name = "srp-env-code"

    def step(
        self, branch: CoWBranch, action: ActionPayload
    ) -> Tuple[StepObservation, float, bool]:
        cmd = action.command
        payload: Dict[str, Any] = action.payload

        if cmd == "read_file":
            target = payload.get("path", "solution.py")
            try:
                content = branch.read_file(target)
                return StepObservation(stdout=content, exit_code=0), 0.0, False
            except FileNotFoundError as exc:
                return StepObservation(stdout="", stderr=str(exc), exit_code=1), 0.0, False

        if cmd in ("apply_patch", "submit_code"):
            target_file = payload.get("path", "solution.py")
            new_code = payload.get("code", "")
            test_file = payload.get("test_path", "test_suite.py")

            # Mutate the CoW branch in volatile RAM (allocates 4KB delta pages)
            branch.write_file(target_file, new_code)

            try:
                _validate_ast_safety(new_code)
                test_code = branch.read_file(test_file)
                _validate_ast_safety(test_code)
            except Exception as exc:
                branch.write_file(".last_run.log", f"VALIDATION_ERROR: {exc}\n")
                return (
                    StepObservation(stdout="", stderr=f"Validation Error: {exc}", exit_code=1),
                    0.0,
                    False,
                )

            stdout_buf = io.StringIO()
            Namespace: Dict[str, Any] = {"__builtins__": dict(SAFE_BUILTINS)}

            try:
                with contextlib.redirect_stdout(stdout_buf):
                    exec(compile(new_code, target_file, "exec"), Namespace)
                    exec(compile(test_code, test_file, "exec"), Namespace)

                # Discover and run all `test_*` functions in test_suite.py
                test_funcs = [
                    (name, fn)
                    for name, fn in sorted(Namespace.items())
                    if name.startswith("test_") and callable(fn)
                ]
                if not test_funcs:
                    branch.write_file(".last_run.log", "PASSED_SCRIPT\n")
                    return (
                        StepObservation(
                            stdout=stdout_buf.getvalue() + "\nAll assertions passed.",
                            exit_code=0,
                        ),
                        1.0,
                        True,
                    )

                passed = 0
                failures = []
                for name, fn in test_funcs:
                    try:
                        with contextlib.redirect_stdout(stdout_buf):
                            fn()
                        passed += 1
                    except Exception as test_exc:
                        failures.append(f"{name}: {type(test_exc).__name__}: {test_exc}")

                total = len(test_funcs)
                reward = round(passed / total, 4)
                terminated = passed == total
                summary = f"Tests Passed: {passed}/{total}"
                branch.write_file(".last_run.log", f"{summary}\n" + "\n".join(failures))

                return (
                    StepObservation(
                        stdout=(stdout_buf.getvalue() + "\n" + summary).strip(),
                        stderr="\n".join(failures),
                        exit_code=0 if terminated else 1,
                        structured_data={"passed": passed, "total": total},
                    ),
                    reward,
                    terminated,
                )
            except Exception as exc:
                branch.write_file(".last_run.log", f"RUNTIME_ERROR: {exc}\n")
                return (
                    StepObservation(
                        stdout=stdout_buf.getvalue(),
                        stderr=f"{type(exc).__name__}: {exc}",
                        exit_code=1,
                    ),
                    0.0,
                    False,
                )

        return (
            StepObservation(stdout="", stderr=f"Unknown command '{cmd}'", exit_code=2),
            0.0,
            False,
        )
