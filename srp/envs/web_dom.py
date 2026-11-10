"""
SRP Flagship Verifier Suite 3: `srp-env-web` (Headless In-Memory DOM / Browser Agent Verifier)
==============================================================================================
Simulates an interactive DOM state machine pinned in Copy-on-Write RAM for training
web navigation and computer-use RL agents without launching heavy Chromium processes
per rollout branch.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Tuple

from srp.node.ram_arena import CoWBranch
from srp.protocol.messages import ActionPayload, StepObservation


class WebDOMVerifier:
    """
    In-memory Headless DOM & Web Interaction Verifier.
    Reads and mutates `dom_state.json` inside the CoW branch.
    Supported actions:
      - `fill_input`: {"selector": "#email", "value": "alice@example.org"}
      - `click`: {"selector": "#submit-btn"}
      - `select_option`: {"selector": "#plan", "value": "pro"}
      - `observe_dom`: returns serialized accessibility tree
    """

    suite_name = "srp-env-web"

    def step(
        self, branch: CoWBranch, action: ActionPayload, timeout_ms: int = 5000
    ) -> Tuple[StepObservation, float, bool]:
        cmd = action.command
        payload: Dict[str, Any] = action.payload if isinstance(action.payload, dict) else {}

        try:
            dom: Dict[str, Any] = json.loads(branch.read_file("dom_state.json"))
        except Exception as exc:
            return (
                StepObservation(stdout="", stderr=f"DOM state error: {exc}", exit_code=1),
                0.0,
                False,
            )

        elements: Dict[str, Dict[str, Any]] = dom.get("elements", {})
        goal_conditions: Dict[str, Any] = dom.get("goal_conditions", {})
        history = dom.get("interaction_log", [])

        goal_already_rewarded = bool(dom.get("_goal_rewarded", False))

        if cmd == "observe_dom":
            tree_str = self._render_a11y_tree(dom)
            return (
                StepObservation(stdout=tree_str, structured_data={"url": dom.get("url", "/")}),
                0.0,
                goal_already_rewarded,
            )

        if goal_already_rewarded:
            # Episode is over: the completion reward was already paid once.
            return (
                StepObservation(
                    stdout=self._render_a11y_tree(dom),
                    stderr="Episode already completed; no further reward",
                    exit_code=0,
                    structured_data={"url": dom.get("url", "/"), "goal_reached": True},
                ),
                0.0,
                True,
            )

        selector = str(payload.get("selector", ""))
        if selector not in elements:
            return (
                StepObservation(
                    stdout=self._render_a11y_tree(dom),
                    stderr=f"Element '{selector}' not found in DOM",
                    exit_code=1,
                ),
                0.0,
                False,
            )

        el = elements[selector]

        if cmd in ("fill_input", "select_option"):
            val = str(payload.get("value", ""))
            el["value"] = val
            history.append({"action": cmd, "selector": selector, "value": val})

        elif cmd == "click":
            el["clicked"] = True
            history.append({"action": "click", "selector": selector})
            # Trigger any declarative on_click state transitions
            for target_key, target_val in el.get("on_click_set", {}).items():
                dom[target_key] = target_val
            if "navigate_to" in el:
                dom["url"] = el["navigate_to"]
        else:
            return (
                StepObservation(
                    stdout="", stderr=f"Unsupported DOM command '{cmd}'", exit_code=2
                ),
                0.0,
                False,
            )

        dom["interaction_log"] = history
        # Re-read elements and goal_conditions in case `on_click_set` updated them
        elements = dom.get("elements", {})
        goal_conditions = dom.get("goal_conditions", {})
        prev_best_matched = int(dom.get("_max_matched_checks", 0))

        reward, terminated, matched_count = self._evaluate_goal(
            dom, elements, goal_conditions, prev_best_matched
        )
        if matched_count > prev_best_matched:
            dom["_max_matched_checks"] = matched_count
        if terminated:
            dom["_goal_rewarded"] = True

        branch.write_file("dom_state.json", json.dumps(dom, indent=2))

        return (
            StepObservation(
                stdout=self._render_a11y_tree(dom),
                exit_code=0,
                structured_data={
                    "url": dom.get("url", "/"),
                    "goal_reached": terminated,
                },
            ),
            reward,
            terminated,
        )

    @staticmethod
    def _render_a11y_tree(dom: Dict[str, Any]) -> str:
        lines = [f"[Page URL: {dom.get('url', '/')}]"]
        for sel, props in sorted(dom.get("elements", {}).items()):
            tag = props.get("tag", "div")
            label = props.get("label", "")
            val = props.get("value", "")
            clicked = " (clicked)" if props.get("clicked") else ""
            lines.append(f"  {sel} <{tag}> label='{label}' value='{val}'{clicked}")
        return "\n".join(lines)

    @staticmethod
    def _evaluate_goal(
        dom: Dict[str, Any],
        elements: Dict[str, Dict[str, Any]],
        goal: Dict[str, Any],
        prev_best_matched: int = 0,
    ) -> Tuple[float, bool, int]:
        if not goal:
            return 0.0, False, 0

        checks = 0
        matched = 0

        for sel, expected_val in goal.get("required_values", {}).items():
            checks += 1
            if elements.get(sel, {}).get("value") == expected_val:
                matched += 1

        for sel in goal.get("required_clicks", []):
            checks += 1
            if elements.get(sel, {}).get("clicked") is True:
                matched += 1

        if "required_url" in goal:
            checks += 1
            if dom.get("url") == goal["required_url"]:
                matched += 1

        if checks == 0:
            return 0.0, False, 0

        if matched == checks:
            return 1.0, True, matched
        if matched > prev_best_matched:
            return round((matched / checks) * 0.5, 4), False, matched
        return 0.0, False, matched
