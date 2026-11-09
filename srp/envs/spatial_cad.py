"""
SRP Flagship Verifier Suite 4: `srp-env-spatial` (3D CAD Geometry & Physics Verifier)
=====================================================================================
Evaluates parametric 3D CAD primitives, boolean assemblies, bounding boxes, volume/mass
constraints, and static stability in Copy-on-Write RAM for training spatial/engineering
AI models.
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Tuple

from srp.node.ram_arena import CoWBranch
from srp.protocol.messages import ActionPayload, StepObservation


class SpatialCADVerifier:
    """
    In-memory 3D CAD & Structural Geometry Verifier.
    Evaluates a parametric scene stored in `cad_scene.json` inside the CoW branch.
    Supported primitives: `box`, `cylinder`, `sphere`.
    Verifies:
      1. Total solid volume within target tolerance
      2. Overall bounding box fits inside the build envelope
      3. Center of mass (CoM) X/Y projection falls within the base support footprint
         (static stability / no-tipping constraint)
    """

    suite_name = "srp-env-spatial"

    def step(
        self, branch: CoWBranch, action: ActionPayload
    ) -> Tuple[StepObservation, float, bool]:
        cmd = action.command
        payload: Dict[str, Any] = action.payload

        try:
            scene: Dict[str, Any] = json.loads(branch.read_file("cad_scene.json"))
        except Exception as exc:
            return (
                StepObservation(stdout="", stderr=f"CAD scene error: {exc}", exit_code=1),
                0.0,
                False,
            )

        primitives: List[Dict[str, Any]] = list(scene.get("primitives", []))
        spec: Dict[str, Any] = scene.get("design_spec", {})

        if cmd == "add_primitive":
            prim = payload.get("primitive")
            if not isinstance(prim, dict) or "type" not in prim:
                return (
                    StepObservation(stdout="", stderr="Invalid primitive definition", exit_code=1),
                    0.0,
                    False,
                )
            primitives.append(prim)
            scene["primitives"] = primitives
            branch.write_file("cad_scene.json", json.dumps(scene, indent=2))

        elif cmd == "set_assembly":
            new_prims = payload.get("primitives", [])
            if not isinstance(new_prims, list):
                return (
                    StepObservation(stdout="", stderr="'primitives' must be a list", exit_code=1),
                    0.0,
                    False,
                )
            primitives = new_prims
            scene["primitives"] = primitives
            branch.write_file("cad_scene.json", json.dumps(scene, indent=2))

        elif cmd != "evaluate_scene":
            return (
                StepObservation(stdout="", stderr=f"Unknown CAD command '{cmd}'", exit_code=2),
                0.0,
                False,
            )

        metrics = self._compute_geometry_metrics(primitives)
        branch.write_file("cad_report.json", json.dumps(metrics, indent=2))

        reward, passed, report_lines = self._grade_against_spec(metrics, spec)
        return (
            StepObservation(
                stdout="\n".join(report_lines),
                exit_code=0 if passed else 1,
                structured_data=metrics,
            ),
            reward,
            passed,
        )

    @staticmethod
    def _compute_geometry_metrics(primitives: List[Dict[str, Any]]) -> Dict[str, Any]:
        total_vol = 0.0
        weighted_com = [0.0, 0.0, 0.0]
        min_pt = [float("inf"), float("inf"), float("inf")]
        max_pt = [float("-inf"), float("-inf"), float("-inf")]

        for p in primitives:
            ptype = p.get("type", "box")
            cx, cy, cz = p.get("center", [0.0, 0.0, 0.0])
            op = p.get("operation", "union")  # "union" or "subtract"
            sign = -1.0 if op == "subtract" else 1.0

            if ptype == "box":
                dx, dy, dz = p.get("size", [1.0, 1.0, 1.0])
                vol = float(dx * dy * dz)
                half = [dx / 2.0, dy / 2.0, dz / 2.0]
            elif ptype == "cylinder":
                r = float(p.get("radius", 1.0))
                h = float(p.get("height", 1.0))
                vol = math.pi * (r ** 2) * h
                half = [r, r, h / 2.0]
            elif ptype == "sphere":
                r = float(p.get("radius", 1.0))
                vol = (4.0 / 3.0) * math.pi * (r ** 3)
                half = [r, r, r]
            else:
                continue

            signed_vol = sign * vol
            total_vol += signed_vol
            weighted_com[0] += signed_vol * cx
            weighted_com[1] += signed_vol * cy
            weighted_com[2] += signed_vol * cz

            if sign > 0:
                for i, c in enumerate((cx, cy, cz)):
                    min_pt[i] = min(min_pt[i], c - half[i])
                    max_pt[i] = max(max_pt[i], c + half[i])

        if total_vol > 1e-9:
            com = [round(c / total_vol, 4) for c in weighted_com]
        else:
            com = [0.0, 0.0, 0.0]

        if min_pt[0] == float("inf"):
            bbox_size = [0.0, 0.0, 0.0]
        else:
            bbox_size = [round(max_pt[i] - min_pt[i], 4) for i in range(3)]

        return {
            "primitive_count": len(primitives),
            "net_volume": round(max(0.0, total_vol), 4),
            "center_of_mass": com,
            "bounding_box_size": bbox_size,
        }

    @staticmethod
    def _grade_against_spec(
        metrics: Dict[str, Any], spec: Dict[str, Any]
    ) -> Tuple[float, bool, List[str]]:
        if not spec:
            return 1.0, True, [f"Evaluated scene: {metrics}"]

        score = 0.0
        checks = 0
        lines = [
            f"Net Volume: {metrics['net_volume']} | BBox: {metrics['bounding_box_size']} | CoM: {metrics['center_of_mass']}"
        ]

        # 1. Target volume check
        if "target_volume" in spec:
            checks += 1
            target_v = float(spec["target_volume"])
            tol = float(spec.get("volume_tolerance", 5.0))
            err = abs(metrics["net_volume"] - target_v)
            if err <= tol:
                score += 1.0
                lines.append(f"[PASS] Volume {metrics['net_volume']} within {target_v} ± {tol}")
            else:
                lines.append(f"[FAIL] Volume {metrics['net_volume']} outside {target_v} ± {tol}")

        # 2. Max bounding envelope check
        if "max_bbox" in spec:
            checks += 1
            max_b = spec["max_bbox"]
            b = metrics["bounding_box_size"]
            if all(b[i] <= max_b[i] and b[i] > 0 for i in range(3)):
                score += 1.0
                lines.append(f"[PASS] Bounding box {b} fits inside envelope {max_b}")
            else:
                lines.append(f"[FAIL] Bounding box {b} exceeds envelope {max_b}")

        # 3. Static stability / Center-of-Mass check
        if "max_com_xy_offset" in spec:
            checks += 1
            max_offset = float(spec["max_com_xy_offset"])
            com_x, com_y, _ = metrics["center_of_mass"]
            radial_offset = math.hypot(com_x, com_y)
            if radial_offset <= max_offset and metrics["net_volume"] > 0:
                score += 1.0
                lines.append(f"[PASS] Static stability CoM XY offset {radial_offset:.3f} <= {max_offset}")
            else:
                lines.append(f"[FAIL] Static stability CoM XY offset {radial_offset:.3f} > {max_offset}")

        if checks == 0:
            return 1.0, True, lines

        final_reward = round(score / checks, 4)
        return final_reward, (score == checks), lines
