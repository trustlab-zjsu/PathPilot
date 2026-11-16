# -*- coding: utf-8 -*-
"""Runtime recorder for the confirmation oracle.

It records findings after execution. It does not inject candidates, mutate
the population, or change generator, crossover, or selection.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from fuzzer.oracles.catalog import load_catalog, match_specs, primary_spec, to_audit_spec
from fuzzer.oracles.evaluate import evaluate_trace


def _text(value: Any) -> str:
    if value in (None, ""):
        return ""
    return str(value)


class LogicOracleRuntime:
    def __init__(
        self,
        output_dir: str,
        contract_name: str = "",
        source_path: str = "",
        address: str = "",
        catalog_path: str = "",
    ) -> None:
        self.output_dir = output_dir or ""
        self.contract_name = contract_name or ""
        self.source_path = source_path or ""
        self.address = address or ""
        self.catalog = load_catalog(catalog_path or None)
        self.specs = match_specs(self.catalog, contract_name, address, source_path)
        self.primary = primary_spec(self.specs)
        self.findings: List[Dict[str, Any]] = []
        self.observed_sequences = 0
        self.best_level = "none"
        if self.output_dir:
            os.makedirs(self.output_dir, exist_ok=True)

    def audit_spec(self) -> Dict[str, Any]:
        if not self.primary:
            return {}
        return to_audit_spec(self.primary)

    def observe(self, events: List[Dict[str, Any]], sequence_id: str = "") -> List[Dict[str, Any]]:
        self.observed_sequences += 1
        if not events or not self.specs:
            return []
        rank = {"none": 0, "L1": 1, "L2": 2, "L3": 3}
        fresh = []
        for spec in self.specs:
            result = evaluate_trace(events, spec)
            result["sequence_id"] = sequence_id
            result["catalog_id"] = spec.get("id")
            result["contract"] = spec.get("contract") or self.contract_name
            if rank.get(result.get("level"), 0) > rank.get(self.best_level, 0):
                self.best_level = result.get("level") or "none"
            if result.get("l3"):
                self.findings.append(result)
                fresh.append(result)
        return fresh

    def finalize(self) -> Dict[str, Any]:
        summary = {
            "enabled": True,
            "contract": self.contract_name,
            "source": self.source_path,
            "matched_spec_count": len(self.specs),
            "primary_oracle_family": (self.primary or {}).get("oracle_family", ""),
            "observed_sequences": self.observed_sequences,
            "confirmed_count": len(self.findings),
            "best_level": self.best_level,
            "search_unchanged": True,
        }
        if self.output_dir:
            findings_path = os.path.join(self.output_dir, "logic_oracle_findings.jsonl")
            with open(findings_path, "w", encoding="utf-8") as handle:
                for item in self.findings:
                    handle.write(json.dumps(item, ensure_ascii=True) + "\n")
            summary_path = os.path.join(self.output_dir, "logic_oracle_summary.json")
            with open(summary_path, "w", encoding="utf-8") as handle:
                json.dump(summary, handle, ensure_ascii=True, indent=2)
            summary["findings_path"] = findings_path
            summary["summary_path"] = summary_path
        return summary


def events_from_tx(tx_index: int, function_name: str, sender: Any, arguments: Any, status: Dict[str, Any]) -> List[Dict[str, Any]]:
    success = status.get("success")
    reverted = bool(status.get("revert") or status.get("reverted"))
    error = _text(status.get("revert_reason") or status.get("error"))
    call = {
        "event_type": "function_call",
        "function": function_name,
        "sender": sender,
        "tx_index": tx_index,
        "args": arguments if isinstance(arguments, (list, dict)) else [],
        "success": success,
        "reverted": reverted,
        "error": error,
    }
    end = {
        "event_type": "tx_end",
        "function": function_name,
        "sender": sender,
        "tx_index": tx_index,
        "success": success,
        "reverted": reverted,
        "error": error,
    }
    return [call, end]
