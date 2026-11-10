"""
SRP Flagship Verifier Suite 1: `srp-env-code` (Code & SWE Unit-Test Verifier)
=============================================================================
Stores code patches in a Copy-on-Write (CoW) branch and grades them against the
snapshot's pinned `test_suite.py`. Agent code is executed only inside the
isolated, resource-limited child interpreter in `srp.envs.sandbox`.
"""

from __future__ import annotations

import ast
import hashlib
from typing import Any, Dict, List, Tuple

from srp.envs.sandbox import SandboxPolicyError, run_test_job, validate_code
from srp.node.ram_arena import CoWBranch
from srp.protocol.messages import ActionPayload, StepObservation

PINNED_TEST_FILE = "test_suite.py"
LOG_FILE = ".last_run.log"
# Optional snapshot secret mixed into the property-test seed. Hidden and read-only.
PROPERTY_SALT_FILE = ".srp_property_salt"
PROTECTED_FILES = (PINNED_TEST_FILE, LOG_FILE, PROPERTY_SALT_FILE)


def property_seed(test_code: str, salt: str, target_file: str, solution_code: str) -> int:
    """
    Seed for the tests' `srp_randint` / `srp_choice` / `srp_random` helpers.

    It depends on the hidden tests, the hidden salt and the submitted code, so
    an agent cannot know the inputs before it submits, and every new submission
    is graded on fresh inputs. It is still a pure function of branch state, so
    replay audits reproduce it exactly.
    """
    h = hashlib.sha256()
    for part in ("SRP_PROPERTY_SEED_V1", test_code, salt, target_file, solution_code):
        data = part.encode("utf-8")
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    return int.from_bytes(h.digest()[:8], "big")


def _validate_ast_safety(code_str: str) -> ast.AST:
    """Backwards-compatible alias for the sandbox static policy."""
    return validate_code(code_str)


class CodeSWEVerifier:
    """
    In-memory SWE / Code RL environment verifier.
    Supports commands:
      - `apply_patch` / `submit_code`: write source to `solution.py` (or another
        non-test path) in CoW RAM, then run the pinned `test_suite.py`.
      - `read_file`: read a file from the CoW branch (grading files are hidden).

    Pinned tests may call `srp_randint(lo, hi)`, `srp_choice(seq)` and
    `srp_random()` for property-based checks; see `property_seed`.
    """

    suite_name = "srp-env-code"

    def step(
        self, branch: CoWBranch, action: ActionPayload, timeout_ms: int = 5000
    ) -> Tuple[StepObservation, float, bool]:
        cmd = action.command
        payload: Dict[str, Any] = action.payload if isinstance(action.payload, dict) else {}

        if cmd == "read_file":
            target = str(payload.get("path", "solution.py"))
            if target in PROTECTED_FILES:
                # Grading inputs stay hidden so they cannot simply be hard-coded.
                return (
                    StepObservation(
                        stdout="", stderr=f"PermissionError: '{target}' is not readable", exit_code=1
                    ),
                    0.0,
                    False,
                )
            try:
                return StepObservation(stdout=branch.read_file(target), exit_code=0), 0.0, False
            except FileNotFoundError as exc:
                return StepObservation(stdout="", stderr=str(exc), exit_code=1), 0.0, False

        if cmd not in ("apply_patch", "submit_code"):
            return (
                StepObservation(stdout="", stderr=f"Unknown command '{cmd}'", exit_code=2),
                0.0,
                False,
            )

        target_file = str(payload.get("path", "solution.py"))
        new_code = str(payload.get("code", ""))

        # The grading test file is fixed by the snapshot, never chosen by the agent:
        # an agent-supplied `test_path` could point at a file it wrote itself.
        test_file = PINNED_TEST_FILE
        requested_test = payload.get("test_path")
        if requested_test is not None and str(requested_test) != test_file:
            return (
                StepObservation(
                    stdout="",
                    stderr=(
                        f"PermissionError: test_path is fixed to '{test_file}'; "
                        "agent-selected test files are not allowed"
                    ),
                    exit_code=1,
                ),
                0.0,
                False,
            )
        if target_file in PROTECTED_FILES:
            return (
                StepObservation(
                    stdout="",
                    stderr=f"PermissionError: Overwriting {target_file} is prohibited",
                    exit_code=1,
                ),
                0.0,
                False,
            )

        try:
            validate_code(new_code)
            test_code = branch.read_file(test_file)
            test_tree = validate_code(test_code)
        except (SandboxPolicyError, SyntaxError, ValueError, FileNotFoundError) as exc:
            branch.write_file(LOG_FILE, f"VALIDATION_ERROR: {exc}\n")
            return (
                StepObservation(stdout="", stderr=f"Validation Error: {exc}", exit_code=1),
                0.0,
                False,
            )

        # Mutate the CoW branch in volatile RAM after validation succeeds
        branch.write_file(target_file, new_code)

        try:
            salt = branch.read_file(PROPERTY_SALT_FILE)
        except FileNotFoundError:
            salt = ""

        declared_test_names: List[str] = [
            node.name
            for node in getattr(test_tree, "body", [])
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
        ]
        if not declared_test_names:
            branch.write_file(LOG_FILE, "NO_TESTS_FOUND\n")
            return (
                StepObservation(
                    stdout="", stderr=f"No test_* functions found in '{test_file}'", exit_code=1
                ),
                0.0,
                False,
            )

        result = run_test_job(
            solution_code=new_code,
            test_code=test_code,
            test_names=declared_test_names,
            solution_path=target_file,
            test_path=test_file,
            timeout_ms=timeout_ms,
            test_seed=property_seed(test_code, salt, target_file, new_code),
        )
        stdout = result["stdout"]
        meta = {
            "timed_out": bool(result["timed_out"]),
            "fuel_used": int(result["fuel_used"]),
            "fuel_limit": int(result["fuel_limit"]),
            "fuel_exhausted": bool(result["fuel_exhausted"]),
        }

        if result["error"] is not None:
            branch.write_file(LOG_FILE, f"RUNTIME_ERROR: {result['error']}\n")
            return (
                StepObservation(
                    stdout=stdout, stderr=str(result["error"]), exit_code=1, structured_data=meta
                ),
                0.0,
                False,
            )

        passed, total = result["passed"], result["total"]
        if total == 0:
            branch.write_file(LOG_FILE, "NO_TESTS_FOUND\n")
            return (
                StepObservation(
                    stdout=stdout, stderr=f"No test_* functions found in '{test_file}'", exit_code=1
                ),
                0.0,
                False,
            )

        failures = result["failures"]
        reward = round(passed / total, 4)
        terminated = passed == total
        summary = f"Tests Passed: {passed}/{total}"
        branch.write_file(LOG_FILE, f"{summary}\n" + "\n".join(failures))
        return (
            StepObservation(
                stdout=(stdout + "\n" + summary).strip(),
                stderr="\n".join(failures),
                exit_code=0 if terminated else 1,
                structured_data={"passed": passed, "total": total, **meta},
            ),
            reward,
            terminated,
        )
