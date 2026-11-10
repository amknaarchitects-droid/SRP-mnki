"""
SRP Node Identity & Receipt Signatures (Ed25519)
================================================
Every provider node owns an Ed25519 keypair. Receipts, registration proofs and
fraud evidence are signed with the private key and verified by anyone holding
the node's public key, so:

  * the coordinator never needs (and never sees) a node secret,
  * a coordinator cannot forge receipts on a node's behalf, and
  * a FraudProof that carries a signed receipt is checkable by third parties.

The `cryptography` package is used when installed (constant-time, fast). The
pure-Python fallback follows the RFC 8032 reference algorithm; it is correct
but NOT side-channel resistant and is ~100x slower. Install the `crypto` extra
(`pip install share-ram-protocol[crypto]`) for production nodes.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import List, Optional, Tuple

try:  # pragma: no cover - exercised implicitly when installed
    from cryptography.exceptions import InvalidSignature as _InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _Ed25519PrivateKey,
        Ed25519PublicKey as _Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization as _serialization

    HAVE_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - depends on environment
    HAVE_CRYPTOGRAPHY = False

SIGNATURE_SCHEME = "ed25519"


# --------------------------------------------------------------------------- #
# Pure-Python Ed25519 (RFC 8032, section 5.1 / reference code in section 6)    #
# --------------------------------------------------------------------------- #
_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

Point = Tuple[int, int, int, int]


def _point_add(a: Point, b: Point) -> Point:
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _point_mul(s: int, pt: Point) -> Point:
    acc: Point = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            acc = _point_add(acc, pt)
        pt = _point_add(pt, pt)
        s >>= 1
    return acc


def _point_equal(a: Point, b: Point) -> bool:
    if (a[0] * b[2] - b[0] * a[2]) % _P != 0:
        return False
    return (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
assert _GX is not None
_G: Point = (_GX, _GY, 1, _GX * _GY % _P)

# Fixed-base table G * 2^i: base-point multiplication needs only additions.
_G_TABLE: List[Point] = []
_pt = _G
for _ in range(256):
    _G_TABLE.append(_pt)
    _pt = _point_add(_pt, _pt)
del _pt


def _base_mul(s: int) -> Point:
    acc: Point = (0, 1, 1, 0)
    i = 0
    while s > 0:
        if s & 1:
            acc = _point_add(acc, _G_TABLE[i])
        s >>= 1
        i += 1
    return acc


def _compress(pt: Point) -> bytes:
    zinv = pow(pt[2], _P - 2, _P)
    x = pt[0] * zinv % _P
    y = pt[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(data: bytes) -> Optional[Point]:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _expand_seed(seed: bytes) -> Tuple[int, bytes]:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _sha512_modq(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _Q


def _py_public_key(seed: bytes) -> bytes:
    a, _ = _expand_seed(seed)
    return _compress(_base_mul(a))


def _py_sign(seed: bytes, public: bytes, msg: bytes) -> bytes:
    a, prefix = _expand_seed(seed)
    r = _sha512_modq(prefix + msg)
    R = _compress(_base_mul(r))
    h = _sha512_modq(R + public + msg)
    s = (r + h * a) % _Q
    return R + int.to_bytes(s, 32, "little")


def _py_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _decompress(public)
    R = _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _Q:
        return False
    h = _sha512_modq(sig[:32] + public + msg)
    return _point_equal(_base_mul(s), _point_add(R, _point_mul(h, A)))


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #
class NodeKeypair:
    """An Ed25519 identity. The 32-byte seed never leaves the node process."""

    def __init__(self, seed: bytes, force_pure_python: bool = False) -> None:
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be exactly 32 bytes")
        self._seed = bytes(seed)
        self._use_lib = HAVE_CRYPTOGRAPHY and not force_pure_python
        if self._use_lib:
            self._sk = _Ed25519PrivateKey.from_private_bytes(self._seed)
            self._public = self._sk.public_key().public_bytes(
                encoding=_serialization.Encoding.Raw,
                format=_serialization.PublicFormat.Raw,
            )
        else:
            self._sk = None
            self._public = _py_public_key(self._seed)

    @classmethod
    def generate(cls) -> "NodeKeypair":
        return cls(secrets.token_bytes(32))

    @classmethod
    def from_secret(cls, secret: str | bytes) -> "NodeKeypair":
        """Derive a keypair from a 64-hex-char seed, or hash any other secret into one."""
        if isinstance(secret, str):
            s = secret.strip()
            if len(s) == 64:
                try:
                    return cls(bytes.fromhex(s))
                except ValueError:
                    pass
            secret = s.encode("utf-8")
        return cls(hashlib.sha256(b"SRP_NODE_SEED_V1|" + secret).digest())

    @property
    def public_key_hex(self) -> str:
        return self._public.hex()

    def sign(self, message: bytes) -> str:
        if self._use_lib:
            return self._sk.sign(message).hex()
        return _py_sign(self._seed, self._public, message).hex()


def verify_signature(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    """Verify an Ed25519 signature; never raises on malformed input."""
    try:
        public = bytes.fromhex(public_key_hex)
        sig = bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False
    if len(public) != 32 or len(sig) != 64:
        return False
    if HAVE_CRYPTOGRAPHY:
        try:
            _Ed25519PublicKey.from_public_bytes(public).verify(sig, message)
            return True
        except (_InvalidSignature, ValueError):
            return False
    return _py_verify(public, message, sig)


def registration_message(node_id: str, public_key_hex: str, nonce: str) -> bytes:
    """Domain-separated message a node signs to prove possession of its key."""
    return f"SRP_NODE_REGISTER_V1|{node_id}|{public_key_hex}|{nonce}".encode("utf-8")
