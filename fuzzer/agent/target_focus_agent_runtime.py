from __future__ import annotations

"""Public target-focus runtime boundary.

The public release keeps evidence-based target focus and LLM path planning,
while candidate execution and pre-execution candidate rehearsals are
intentionally omitted.  This adapter preserves the runtime interface used by
the normal fuzzer and reports an empty candidate set.
"""

import json
import os
from typing import Any, Dict, Optional


class TFIAgentRuntime:
    """Evidence-facing runtime with candidate execution paths removed."""

    def __init__(self, output_dir: str, *, llm_provider: Any = None, enable_agent: bool = False, **kwargs: Any) -> None:
        self.output_dir = os.path.abspath(output_dir) if output_dir else ""
        self.summary_path = os.path.join(self.output_dir, "target_focus_agent_runtime_summary.json") if self.output_dir else ""
        self.llm_provider = llm_provider
        self.enable_agent = bool(enable_agent)
        self.candidate_execution_enabled = False
        self.tfi_planning_only = True
        self.binding_only = True
        self.candidate_injector = None
        self.candidate_execution_removed = True
        self._last_result: Dict[str, Any] = {}

    def run_once(self) -> Dict[str, Any]:
        result = {
            "enabled": bool(self.enable_agent),
            "agent_enabled": bool(self.enable_agent),
            "agent_called": False,
            "agent_called_count": 0,
            "agent_error_count": 0,
            "llm_called": False,
            "llm_success_count": 0,
            "llm_error_count": 0,
            "candidate_gap_event_count": 0,
            "candidate_gap_guidance_count": 0,
            "guidance_generated_count": 0,
            "fuzzer_generated_candidate_count": 0,
            "candidate_built_count": 0,
            "candidate_executed_count": 0,
            "useful_candidate_count": 0,
            "candidate_records": [],
            "useful_candidate_records": [],
            "candidate_gap_events": [],
            "gap_guidance_records": [],
            "llm_interaction_events": [],
            "llm_interaction_count": 0,
            "llm_interaction_time_total_sec": 0.0,
            "fallback_used": False,
            "skip_reason": "candidate_execution_removed_from_public_release",
            "candidate_generation_disabled": True,
        }
        self._last_result = result
        return result

    def run(self) -> Dict[str, Any]:
        result = self.run_once()
        if self.summary_path:
            try:
                os.makedirs(self.output_dir, exist_ok=True)
                with open(self.summary_path, "w", encoding="utf-8") as handle:
                    json.dump(result, handle, ensure_ascii=True, indent=2)
            except Exception:
                pass
        return result

    def build_summary(self) -> Dict[str, Any]:
        return dict(self._last_result or self.run_once())


__all__ = ["TFIAgentRuntime"]
