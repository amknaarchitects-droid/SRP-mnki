"""
SRP Flagship Verifier Suite 4: `srp-env-spatial` (3D CAD Geometry & Physics Verifier)
=====================================================================================
Evaluates parametric 3D CAD primitives with true constructive solid geometry
(material = union of `union` primitives minus union of `subtract` primitives),
then grades volume, bounding envelope and static stability against the scene's
design spec.

Geometry engine: all primitive bounding-box faces define a coordinate-compressed
grid. In a cell covered only by boxes, membership is constant, so volume, centre
of mass and bounding box are *exact*. Cells touched by a cylinder or sphere are
sub-sampled at a resolution chosen to fit a fixed point budget (deterministic
midpoint rule). Overlapping unions are counted once and a `subtract` only removes
material that exists, so phantom subtractions cannot game volume or CoM.
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Optional, Tuple

from srp.node.ram_arena import CoWBranch
from srp.protocol.messages import ActionPayload, StepObservation

MAX_PRIMITIVES = 16
MAX_ABS_COORD = 1e6
CURVED_SAMPLE_BUDGET = 120_000

Prim = Dict[str, Any]


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(float(v))


def _bounds(p: Prim) -> Tuple[Tuple[float, float], Tuple[float, float], Tuple[float, float]]:
    cx, cy, cz = (float(c) for c in p.get("center", [0.0, 0.0, 0.0]))
    t = p.get("type", "box")
    if t == "box":
        dx, dy, dz = (float(s) for s in p.get("size", [1.0, 1.0, 1.0]))
        hx, hy, hz = dx / 2, dy / 2, dz / 2
    elif t == "cylinder":
        r, h = float(p.get("radius", 1.0)), float(p.get("height", 1.0))
        hx, hy, hz = r, r, h / 2
    else:
        r = float(p.get("radius", 1.0))
        hx = hy = hz = r
    return (cx - hx, cx + hx), (cy - hy, cy + hy), (cz - hz, cz + hz)


def _contains(p: Prim, x: float, y: float, z: float) -> bool:
    cx, cy, cz = (float(c) for c in p.get("center", [0.0, 0.0, 0.0]))
    t = p.get("type", "box")
    if t == "box":
        dx, dy, dz = (float(s) for s in p.get("size", [1.0, 1.0, 1.0]))
        return abs(x - cx) <= dx / 2 and abs(y - cy) <= dy / 2 and abs(z - cz) <= dz / 2
    if t == "cylinder":
        r, h = float(p.get("radius", 1.0)), float(p.get("height", 1.0))
        return (x - cx) ** 2 + (y - cy) ** 2 <= r * r and abs(z - cz) <= h / 2
    r = float(p.get("radius", 1.0))
    return (x - cx) ** 2 + (y - cy) ** 2 + (z - cz) ** 2 <= r * r


def compute_csg_metrics(primitives: List[Prim]) -> Dict[str, Any]:
    """Exact-for-boxes CSG volume, centre of mass and material bounding box."""
    unions = [p for p in primitives if p.get("operation", "union") != "subtract"]
    if not unions:
        return {
            "primitive_count": len(primitives),
            "net_volume": 0.0,
            "center_of_mass": [0.0, 0.0, 0.0],
            "bounding_box_size": [0.0, 0.0, 0.0],
        }

    bounds = [_bounds(p) for p in primitives]
    axes: List[List[float]] = []
    for a in range(3):
        cuts = sorted({b[a][0] for b in bounds} | {b[a][1] for b in bounds})
        axes.append(cuts)

    def cover(a: int, lo: float, hi: float) -> range:
        cuts = axes[a]
        return range(cuts.index(lo), cuts.index(hi))

    # Per primitive: which cell index ranges it covers along each axis
    cell_cover = [tuple(cover(a, b[a][0], b[a][1]) for a in range(3)) for b in bounds]
    curved = [p.get("type", "box") != "box" for p in primitives]
    is_sub = [p.get("operation", "union") == "subtract" for p in primitives]

    nx, ny, nz = (len(axes[a]) - 1 for a in range(3))
    occupied_cells: List[Tuple[int, int, int, List[int]]] = []
    for i in range(nx):
        for j in range(ny):
            for k in range(nz):
                cand = [
                    idx
                    for idx, (rx, ry, rz) in enumerate(cell_cover)
                    if i in rx and j in ry and k in rz
                ]
                if any(not is_sub[idx] for idx in cand):
                    occupied_cells.append((i, j, k, cand))

    curved_cells = sum(1 for *_, cand in occupied_cells if any(curved[c] for c in cand))
    sub = 1
    if curved_cells:
        sub = max(2, min(40, int((CURVED_SAMPLE_BUDGET / curved_cells) ** (1.0 / 3.0))))

    vol = 0.0
    moment = [0.0, 0.0, 0.0]
    lo_pt = [math.inf] * 3
    hi_pt = [-math.inf] * 3

    for i, j, k, cand in occupied_cells:
        x0, x1 = axes[0][i], axes[0][i + 1]
        y0, y1 = axes[1][j], axes[1][j + 1]
        z0, z1 = axes[2][k], axes[2][k + 1]
        n = sub if any(curved[c] for c in cand) else 1
        sx, sy, sz = (x1 - x0) / n, (y1 - y0) / n, (z1 - z0) / n
        dv = sx * sy * sz
        for a in range(n):
            px = x0 + (a + 0.5) * sx
            for b in range(n):
                py = y0 + (b + 0.5) * sy
                for c in range(n):
                    pz = z0 + (c + 0.5) * sz
                    inside = False
                    for idx in cand:
                        if not is_sub[idx] and _contains(primitives[idx], px, py, pz):
                            inside = True
                            break
                    if not inside:
                        continue
                    if any(is_sub[idx] and _contains(primitives[idx], px, py, pz) for idx in cand):
                        continue
                    vol += dv
                    moment[0] += dv * px
                    moment[1] += dv * py
                    moment[2] += dv * pz
                    for ax, (p_, s_) in enumerate(((px, sx), (py, sy), (pz, sz))):
                        lo_pt[ax] = min(lo_pt[ax], p_ - s_ / 2)
                        hi_pt[ax] = max(hi_pt[ax], p_ + s_ / 2)

    if vol <= 1e-12:
        com = [0.0, 0.0, 0.0]
        bbox = [0.0, 0.0, 0.0]
    else:
        com = [round(m / vol, 4) + 0.0 for m in moment]
        bbox = [round(hi_pt[a] - lo_pt[a], 4) for a in range(3)]
    return {
        "primitive_count": len(primitives),
        "net_volume": round(vol, 4),
        "center_of_mass": com,
        "bounding_box_size": bbox,
    }


class SpatialCADVerifier:
    """
    In-memory 3D CAD & Structural Geometry Verifier for `cad_scene.json`.
    Supported primitives: `box`, `cylinder` (Z axis), `sphere`; operations
    `union` / `subtract`. Rewards:
      * mutating commands earn the spec score only when it improves on the best
        score reached so far in this branch; the full-pass reward is paid once;
      * `evaluate_scene` is a pure observation (reward 0.0);
      * a scene without a `design_spec` can never earn reward.
    """

    suite_name = "srp-env-spatial"

    def step(
        self, branch: CoWBranch, action: ActionPayload, timeout_ms: int = 5000
    ) -> Tuple[StepObservation, float, bool]:
        cmd = action.command
        payload: Dict[str, Any] = action.payload if isinstance(action.payload, dict) else {}

        try:
            scene: Dict[str, Any] = json.loads(branch.read_file("cad_scene.json"))
        except Exception as exc:
            return StepObservation(stdout="", stderr=f"CAD scene error: {exc}", exit_code=1), 0.0, False

        primitives: List[Prim] = list(scene.get("primitives", []))
        spec: Dict[str, Any] = scene.get("design_spec", {}) or {}
        best_score = float(scene.get("_best_score", 0.0))
        already_rewarded = bool(scene.get("_goal_rewarded", False))
        mutated = False

        if cmd == "add_primitive":
            prim = payload.get("primitive")
            err = self._validate_primitive(prim)
            if err is None and len(primitives) + 1 > MAX_PRIMITIVES:
                err = f"Scene is limited to {MAX_PRIMITIVES} primitives"
            if err is not None:
                return StepObservation(stdout="", stderr=err, exit_code=1), 0.0, False
            primitives.append(prim)
            mutated = True

        elif cmd == "set_assembly":
            new_prims = payload.get("primitives", [])
            if not isinstance(new_prims, list):
                return (
                    StepObservation(stdout="", stderr="'primitives' must be a list", exit_code=1),
                    0.0,
                    False,
                )
            if len(new_prims) > MAX_PRIMITIVES:
                return (
                    StepObservation(
                        stdout="", stderr=f"Scene is limited to {MAX_PRIMITIVES} primitives", exit_code=1
                    ),
                    0.0,
                    False,
                )
            for idx, prim in enumerate(new_prims):
                err = self._validate_primitive(prim)
                if err is not None:
                    return (
                        StepObservation(
                            stdout="", stderr=f"Invalid primitive at index {idx}: {err}", exit_code=1
                        ),
                        0.0,
                        False,
                    )
            primitives = list(new_prims)
            mutated = True

        elif cmd != "evaluate_scene":
            return (
                StepObservation(stdout="", stderr=f"Unknown CAD command '{cmd}'", exit_code=2),
                0.0,
                False,
            )

        metrics = compute_csg_metrics(primitives)
        score, passed, report_lines = self._grade_against_spec(metrics, spec)

        reward = 0.0
        if mutated:
            if not already_rewarded and score > best_score + 1e-9:
                reward = score
                best_score = score
            if passed:
                already_rewarded = True
            scene["primitives"] = primitives
            scene["_best_score"] = round(best_score, 6)
            scene["_goal_rewarded"] = already_rewarded
            branch.write_file("cad_scene.json", json.dumps(scene, indent=2, sort_keys=True))
            branch.write_file("cad_report.json", json.dumps(metrics, indent=2, sort_keys=True))

        return (
            StepObservation(
                stdout="\n".join(report_lines),
                exit_code=0 if passed else 1,
                structured_data={**metrics, "spec_score": score},
            ),
            round(reward, 4),
            passed,
        )

    @staticmethod
    def _validate_primitive(prim: Any) -> Optional[str]:
        if not isinstance(prim, dict) or "type" not in prim:
            return "Invalid primitive definition: must be a dict with 'type'"
        ptype = prim.get("type")
        if ptype not in ("box", "cylinder", "sphere"):
            return f"Unsupported primitive type '{ptype}'"
        op = prim.get("operation", "union")
        if op not in ("union", "subtract"):
            return f"Unsupported boolean operation '{op}'"
        center = prim.get("center", [0.0, 0.0, 0.0])
        if (
            not isinstance(center, (list, tuple))
            or len(center) != 3
            or not all(_is_num(c) and abs(float(c)) <= MAX_ABS_COORD for c in center)
        ):
            return "'center' must be a 3-element list of finite numbers"

        def _pos(v: Any) -> bool:
            return _is_num(v) and 0.0 < float(v) <= MAX_ABS_COORD

        if ptype == "box":
            size = prim.get("size", [1.0, 1.0, 1.0])
            if not isinstance(size, (list, tuple)) or len(size) != 3 or not all(_pos(s) for s in size):
                return "'size' must be a 3-element list of positive finite numbers"
        elif ptype == "cylinder":
            for k in ("radius", "height"):
                if not _pos(prim.get(k, 1.0)):
                    return f"'{k}' must be a positive finite number"
        elif not _pos(prim.get("radius", 1.0)):
            return "'radius' must be a positive finite number"
        return None

    @staticmethod
    def _grade_against_spec(
        metrics: Dict[str, Any], spec: Dict[str, Any]
    ) -> Tuple[float, bool, List[str]]:
        lines = [
            f"Net Volume: {metrics['net_volume']} | BBox: {metrics['bounding_box_size']} "
            f"| CoM: {metrics['center_of_mass']}"
        ]
        score = 0.0
        checks = 0

        if "target_volume" in spec:
            checks += 1
            target_v = float(spec["target_volume"])
            tol = float(spec.get("volume_tolerance", 5.0))
            if abs(metrics["net_volume"] - target_v) <= tol:
                score += 1.0
                lines.append(f"[PASS] Volume {metrics['net_volume']} within {target_v} ± {tol}")
            else:
                lines.append(f"[FAIL] Volume {metrics['net_volume']} outside {target_v} ± {tol}")

        if "max_bbox" in spec:
            checks += 1
            max_b = spec["max_bbox"]
            b = metrics["bounding_box_size"]
            if all(0 < b[i] <= float(max_b[i]) for i in range(3)):
                score += 1.0
                lines.append(f"[PASS] Bounding box {b} fits inside envelope {max_b}")
            else:
                lines.append(f"[FAIL] Bounding box {b} exceeds envelope {max_b}")

        if "max_com_xy_offset" in spec:
            checks += 1
            max_offset = float(spec["max_com_xy_offset"])
            com_x, com_y, _ = metrics["center_of_mass"]
            radial = math.hypot(com_x, com_y)
            if radial <= max_offset and metrics["net_volume"] > 0:
                score += 1.0
                lines.append(f"[PASS] Static stability CoM XY offset {radial:.3f} <= {max_offset}")
            else:
                lines.append(f"[FAIL] Static stability CoM XY offset {radial:.3f} > {max_offset}")

        if checks == 0:
            lines.append("[FAIL] Scene has no gradeable design_spec; no reward is possible")
            return 0.0, False, lines
        return round(score / checks, 4), score == checks, lines

    # Backwards-compatible name used by older callers
    _compute_geometry_metrics = staticmethod(compute_csg_metrics)
