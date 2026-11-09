"""SRP Flagship Verifier Suites Registry."""

from srp.envs.code_swe import CodeSWEVerifier
from srp.envs.math_lean import MathLeanVerifier
from srp.envs.web_dom import WebDOMVerifier
from srp.envs.spatial_cad import SpatialCADVerifier

VERIFIER_REGISTRY = {
    CodeSWEVerifier.suite_name: CodeSWEVerifier(),
    MathLeanVerifier.suite_name: MathLeanVerifier(),
    WebDOMVerifier.suite_name: WebDOMVerifier(),
    SpatialCADVerifier.suite_name: SpatialCADVerifier(),
}

__all__ = [
    "CodeSWEVerifier",
    "MathLeanVerifier",
    "WebDOMVerifier",
    "SpatialCADVerifier",
    "VERIFIER_REGISTRY",
]
