# -*- coding: utf-8 -*-
"""PathPilot confirmation oracle.

The thirteen families are independent of candidate generation. Enable the
runtime recorder with --enable-logic-oracle. Existing traces can be scored
with fuzzer.oracles.evaluate without launching a new fuzzing run.
"""

from fuzzer.oracles.evaluate import evaluate_trace
from fuzzer.oracles.families import FAMILY_ORDER

__all__ = ["FAMILY_ORDER", "evaluate_trace"]
