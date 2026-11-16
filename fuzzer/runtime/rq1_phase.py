from __future__ import annotations

from typing import Any, Dict, Optional


RQ1_CONFIGS: Dict[str, Dict[str, int]] = {}


def normalize_rq1_config(value: Any) -> str:
    return ""


def rq1_budget_for_config(value: Any) -> Dict[str, int]:
    return {}


def build_rq1_phase_state(args: Any) -> Dict[str, Any]:
    return {
        "enabled": False,
        "config": "",
        "g_sec": 0,
        "k_sec": 0,
        "t_sec": 0,
        "total_sec": 0,
        "k_start_sec": 0,
        "t_start_sec": 0,
    }


def ensure_rq1_phase_state(env: Any, args: Optional[Any] = None) -> Dict[str, Any]:
    state = getattr(env, "rq1_phase_state", None)
    if not isinstance(state, dict):
        state = build_rq1_phase_state(args or getattr(env, "args", None))
        setattr(env, "rq1_phase_state", state)
    return state


def rq1_current_phase(env: Any, args: Optional[Any] = None, elapsed_sec: Optional[float] = None) -> str:
    return ""


def rq1_phase_allows_feature(env: Any, feature: str, args: Optional[Any] = None) -> bool:
    return True
