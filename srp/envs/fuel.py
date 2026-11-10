"""
Deterministic Fuel Metering for the Code Sandbox
================================================
Wall-clock timeouts are not reproducible: the same step can finish on a fast
node and time out on a slower auditor, which would turn honest nodes into
"fraudsters" under replay audits. SRP therefore bounds agent code with *fuel*,
a deterministic instruction budget (in the spirit of WASM fuel metering):

  * every loop iteration, function/lambda call and comprehension item costs
    one unit (`__srp_tick__` / `__srp_iter__` are injected by an AST pass);
  * iteration-consuming builtins (`sum`, `sorted`, `list`, ...) are charged per
    element consumed;
  * `**`, `*` and `<<` are routed through guards that refuse integer results
    above `MAX_INT_BITS` and sequence repetition above `MAX_SEQ_ITEMS`, which
    would otherwise burn unmetered C time.

Exhausting fuel raises `FuelExhausted` (a BaseException, so `except Exception`
cannot swallow it), at exactly the same point on every machine running the same
CPython runtime profile. The wall-clock deadline remains only as a backstop
for pathological C-level work; a backstop hit is reported as `timed_out` and
treated as *inconclusive* by audits.

Instrumentation runs after `sandbox.validate_code`, so agent code cannot name or
tamper with the injected `__srp_*__` hooks (dunder names are rejected).
"""

from __future__ import annotations

import ast

TICK = "__srp_tick__"
ITER = "__srp_iter__"
POW = "__srp_pow__"
MUL = "__srp_mul__"
LSHIFT = "__srp_lshift__"

FUEL_PER_MS = 2_000  # conservative: fuel always runs out before the wall-clock backstop
MAX_INT_BITS = 4_000_000
MAX_SEQ_ITEMS = 20_000_000

_GUARDED_BINOPS = {ast.Pow: POW, ast.Mult: MUL, ast.LShift: LSHIFT}


def fuel_for_timeout(timeout_ms: int) -> int:
    return max(10_000, int(timeout_ms) * FUEL_PER_MS)


def _call(name: str, args):
    return ast.Call(func=ast.Name(id=name, ctx=ast.Load()), args=list(args), keywords=[])


def _tick_stmt() -> ast.stmt:
    return ast.Expr(value=_call(TICK, []))


class _Instrumenter(ast.NodeTransformer):
    def _prefix_tick(self, node):
        self.generic_visit(node)
        node.body.insert(0, _tick_stmt())
        return node

    visit_FunctionDef = _prefix_tick
    visit_For = _prefix_tick
    visit_While = _prefix_tick

    def visit_Lambda(self, node: ast.Lambda):
        self.generic_visit(node)
        # lambda: body  ->  lambda: (__srp_tick__(), body)[1]
        node.body = ast.Subscript(
            value=ast.Tuple(elts=[_call(TICK, []), node.body], ctx=ast.Load()),
            slice=ast.Constant(value=1),
            ctx=ast.Load(),
        )
        return node

    def visit_comprehension(self, node: ast.comprehension):
        self.generic_visit(node)
        node.iter = _call(ITER, [node.iter])
        return node

    def visit_BinOp(self, node: ast.BinOp):
        self.generic_visit(node)
        guard = _GUARDED_BINOPS.get(type(node.op))
        if guard is None:
            return node
        return ast.copy_location(_call(guard, [node.left, node.right]), node)

    def visit_AugAssign(self, node: ast.AugAssign):
        self.generic_visit(node)
        guard = _GUARDED_BINOPS.get(type(node.op))
        if guard is None or not isinstance(node.target, ast.Name):
            # Subscript/attribute targets keep native semantics (backstopped by the
            # memory cap and wall-clock deadline).
            return node
        load = ast.Name(id=node.target.id, ctx=ast.Load())
        return ast.copy_location(
            ast.Assign(
                targets=[ast.Name(id=node.target.id, ctx=ast.Store())],
                value=_call(guard, [load, node.value]),
            ),
            node,
        )


def instrument(tree: ast.Module) -> str:
    """Return instrumented source for an already-validated module AST."""
    tree = _Instrumenter().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


# --------------------------------------------------------------------------- #
# Runtime support, embedded verbatim into the sandbox child program.          #
# Defines `_make_fuel(limit, safe_builtins) -> dict of injected names`.        #
# --------------------------------------------------------------------------- #
RUNTIME_SOURCE = r'''
class FuelExhausted(BaseException):
    pass

def _make_fuel(limit, safe, max_bits, max_items):
    state = [0]
    def tick():
        state[0] += 1
        if state[0] > limit:
            raise FuelExhausted("fuel exhausted after %d units" % limit)
    def charge(n):
        state[0] += n
        if state[0] > limit:
            raise FuelExhausted("fuel exhausted after %d units" % limit)
    def it(iterable):
        for item in iterable:
            tick()
            yield item
    def _int_bits(v):
        return v.bit_length() if isinstance(v, int) and not isinstance(v, bool) else 0
    def _seq_len(v):
        return len(v) if isinstance(v, (str, bytes, list, tuple)) else -1
    def pow_(a, b, *mod):
        if not mod and isinstance(a, int) and isinstance(b, int) and b > 0 and abs(a) > 1:
            if _int_bits(a) * b > max_bits:
                raise OverflowError("integer result too large for the sandbox")
            charge(_int_bits(a) * b // 4096)
        return _real_pow(a, b, *mod)
    def mul(a, b):
        la, lb = _seq_len(a), _seq_len(b)
        if la >= 0 and isinstance(b, int):
            if la * max(b, 0) > max_items:
                raise MemoryError("sequence repetition too large for the sandbox")
            charge(la * max(b, 0) // 4096)
        elif lb >= 0 and isinstance(a, int):
            if lb * max(a, 0) > max_items:
                raise MemoryError("sequence repetition too large for the sandbox")
            charge(lb * max(a, 0) // 4096)
        elif _int_bits(a) + _int_bits(b) > max_bits:
            raise OverflowError("integer result too large for the sandbox")
        else:
            charge((_int_bits(a) * _int_bits(b)) // (1 << 20))
        return a * b
    def lshift(a, b):
        if isinstance(b, int) and _int_bits(a) + max(b, 0) > max_bits:
            raise OverflowError("integer result too large for the sandbox")
        return a << b
    _real_pow = safe.get("pow", pow)
    def _metered(fn):
        def wrapper(*args, **kwargs):
            if args:
                args = (it(args[0]),) + args[1:]
            return fn(*args, **kwargs)
        wrapper.__name__ = getattr(fn, "__name__", "builtin")
        return wrapper
    for name in ("sum", "sorted", "list", "tuple", "set", "frozenset", "min", "max", "any", "all"):
        if name in safe:
            real = safe[name]
            if name in ("min", "max"):
                # min/max(a, b, ...) with several positional args is not an iteration
                def _mm(*args, _real=real, **kwargs):
                    if len(args) == 1:
                        return _real(it(args[0]), **kwargs)
                    charge(len(args))
                    return _real(*args, **kwargs)
                safe[name] = _mm
            else:
                safe[name] = _metered(real)
    safe["pow"] = pow_
    hooks = {"__srp_tick__": tick, "__srp_iter__": it, "__srp_pow__": pow_,
             "__srp_mul__": mul, "__srp_lshift__": lshift}
    return hooks, state
'''
