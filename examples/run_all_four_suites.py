"""
End-to-End Example: Running GRPO & MCTS Branching Rollouts Across All 4 SRP Suites
==================================================================================
Run with:
    python examples/run_all_four_suites.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srp.cli import run_demo  # noqa: E402

if __name__ == "__main__":
    run_demo()
