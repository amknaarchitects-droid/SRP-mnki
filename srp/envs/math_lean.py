"""
SRP Flagship Verifier Suite 2: `srp-env-math` (Formal Math & Lean-Style Proof Verifier)
=======================================================================================
Maintains pre-warmed theorem proof states in Copy-on-Write RAM so AI reasoning models
can explore branching tactic trees (MCTS / GRPO) without reloading heavy math libraries.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from srp.node.ram_arena import CoWBranch
from srp.protocol.messages import ActionPayload, StepObservation


class MathLeanVerifier:
    """
    In-memory Formal Proof & Symbolic Tactic Verifier.
    Reads `theorem_state.json` from the CoW branch, applies a tactic step (`apply_tactic`),
    updates the remaining proof goals in CoW RAM, and emits a verifiable reward:
      - `1.0` when all goals are discharged (`goals == []`)
      - Partial shaping reward (`0.1` to `0.5`) when sub-goals are validly reduced
      - `0.0` on invalid tactic application
    """

    suite_name = "srp-env-math"

    def step(
        self, branch: CoWBranch, action: ActionPayload, timeout_ms: int = 5000
    ) -> Tuple[StepObservation, float, bool]:
        cmd = action.command
        payload: Dict[str, Any] = action.payload if isinstance(action.payload, dict) else {}

        try:
            raw_state = branch.read_file("theorem_state.json")
            state: Dict[str, Any] = json.loads(raw_state)
        except Exception as exc:
            return (
                StepObservation(
                    stdout="",
                    stderr=f"Failed to load theorem_state.json from RAM: {exc}",
                    exit_code=1,
                ),
                0.0,
                False,
            )

        goals: List[str] = list(state.get("goals", []))
        valid_rules: Dict[str, List[str]] = state.get("tactic_transitions", {})
        proof_trace: List[str] = list(state.get("proof_trace", []))
        visited_states: List[str] = list(
            state.get("visited_goal_states", ["||".join(goals)])
        )

        if cmd == "inspect_goals":
            formatted = (
                "\n".join(f"Goal {i+1}: {g}" for i, g in enumerate(goals))
                or "No goals."
            )
            return (
                StepObservation(
                    stdout=formatted,
                    structured_data={"goals": goals, "proof_trace": proof_trace},
                ),
                0.0,
                len(goals) == 0,
            )

        if cmd == "apply_tactic":
            tactic = str(payload.get("tactic", "")).strip()
            if not goals:
                # The completion reward is paid exactly once, on the closing tactic.
                return (
                    StepObservation(stdout="Goals already accomplished!", exit_code=0),
                    0.0,
                    True,
                )

            current_goal = goals[0]
            transition_key = f"{current_goal}::{tactic}"

            # Check transition table or built-in symbolic rewrite rules
            if transition_key in valid_rules:
                replacement_goals = valid_rules[transition_key]
                new_goals = replacement_goals + goals[1:]
            elif tactic in valid_rules:
                replacement_goals = valid_rules[tactic]
                new_goals = replacement_goals + goals[1:]
            elif self._check_builtin_algebraic_tactic(current_goal, tactic):
                new_goals = goals[1:]
            else:
                return (
                    StepObservation(
                        stdout="",
                        stderr=f"Tactic '{tactic}' failed on goal: {current_goal}",
                        exit_code=1,
                        structured_data={"goals": goals},
                    ),
                    0.0,
                    False,
                )

            new_goal_sig = "||".join(new_goals)
            is_novel_state = new_goal_sig not in visited_states
            if is_novel_state:
                visited_states.append(new_goal_sig)

            proof_trace.append(tactic)
            state["goals"] = new_goals
            state["proof_trace"] = proof_trace
            state["visited_goal_states"] = visited_states

            # Write updated proof state & Lean script into CoW RAM delta pages
            branch.write_file("theorem_state.json", json.dumps(state, indent=2))
            branch.write_file("ProofHistory.lean", "\n".join(proof_trace) + "\n")

            if len(new_goals) == 0:
                return (
                    StepObservation(
                        stdout="Goals accomplished! QED.",
                        exit_code=0,
                        structured_data={"goals": [], "proof_trace": proof_trace},
                    ),
                    1.0,
                    True,
                )

            # Award partial progress reward only when reaching a novel proof state
            if not is_novel_state:
                progress_reward = 0.0
            elif len(new_goals) < len(goals):
                progress_reward = 0.25
            else:
                progress_reward = 0.1

            remaining_str = "\n".join(
                f"Goal {i+1}: {g}" for i, g in enumerate(new_goals)
            )
            return (
                StepObservation(
                    stdout=f"Tactic '{tactic}' succeeded.\n{remaining_str}",
                    exit_code=0,
                    structured_data={"goals": new_goals, "proof_trace": proof_trace},
                ),
                progress_reward,
                False,
            )

        return (
            StepObservation(
                stdout="", stderr=f"Unknown math command '{cmd}'", exit_code=2
            ),
            0.0,
            False,
        )

    @staticmethod
    def _check_builtin_algebraic_tactic(goal: str, tactic: str) -> bool:
        """Built-in lightweight reflexivity / symmetry / omega verifier."""
        norm_goal = goal.replace(" ", "")
        # Reject non-equality relational operators before splitting on '='
        if any(op in norm_goal for op in ("!=", "<=", ">=", "==")):
            return False
        if norm_goal.count("=") != 1:
            return False

        lhs, rhs = norm_goal.split("=", 1)
        if not lhs or not rhs:
            return False

        if tactic in ("rfl", "refl"):
            return lhs == rhs

        if tactic in ("ring", "omega"):
            if lhs == rhs:
                return True
            # Associative/commutative addition check (strip grouping parentheses when only '+' is present)
            if "+" in lhs and "+" in rhs:
                if not any(op in norm_goal for op in ("-", "*", "/", "^")):
                    clean_lhs = lhs.replace("(", "").replace(")", "")
                    clean_rhs = rhs.replace("(", "").replace(")", "")
                    terms_l = [t for t in clean_lhs.split("+") if t]
                    terms_r = [t for t in clean_rhs.split("+") if t]
                    if terms_l and sorted(terms_l) == sorted(terms_r):
                        return True
        return False
