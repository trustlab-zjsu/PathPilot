# -*- coding: utf-8 -*-
"""Load the written-back PathPilot oracle catalog."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


CATALOG_PATH = Path(__file__).resolve().parent / "catalog" / "logic_oracle_catalog.json"


def load_catalog(path: Optional[str] = None) -> Dict[str, Any]:
    target = Path(path) if path else CATALOG_PATH
    if not target.exists():
        return {"specs": [], "summary": {}, "families": []}
    payload = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return {"specs": [], "summary": {}, "families": []}
    payload.setdefault("specs", [])
    return payload


def _norm(value: Any) -> str:
    return "" if value in (None, "") else str(value).strip().lower()


def _norm_path(value: Any) -> str:
    return _norm(value).replace("/", '\\')


def _aliases(spec: Dict[str, Any]) -> List[str]:
    values = [spec.get("source") or ""]
    extra = spec.get("source_aliases") or []
    if isinstance(extra, str):
        extra = [extra]
    values.extend(extra)
    found = []
    for value in values:
        text = _norm_path(value)
        if text and text not in found:
            found.append(text)
    return found


def _source_hit(source: str, spec: Dict[str, Any]) -> bool:
    current = _norm_path(source)
    if not current:
        return False
    current_name = Path(current).name
    for alias in _aliases(spec):
        if current == alias or current_name == Path(alias).name:
            return True
        if current_name and current_name == Path(alias).name:
            return True
    address = _norm(spec.get("address"))
    if address and address in current:
        return True
    bench = _norm(spec.get("bench_contract_id"))
    if bench and bench in current:
        return True
    return False


def match_specs(
    catalog: Dict[str, Any],
    contract_name: str = "",
    address: str = "",
    source_path: str = "",
) -> List[Dict[str, Any]]:
    name = _norm(contract_name)
    addr = _norm(address)
    source = source_path or ""
    specs = [item for item in (catalog.get("specs") or []) if isinstance(item, dict) and item.get("oracle_family")]
    matched = []
    for spec in specs:
        spec_name = _norm(spec.get("contract"))
        spec_addr = _norm(spec.get("address"))
        bench = _norm(spec.get("bench_contract_id"))
        if addr and spec_addr and addr == spec_addr:
            matched.append(spec)
            continue
        if source and _source_hit(source, spec):
            matched.append(spec)
            continue
        if name and bench and name == bench:
            matched.append(spec)
            continue
        if (
            name
            and spec_name
            and name == spec_name
            and spec.get("origin") != "static_source"
            and _unique_contract_name(specs, spec_name)
        ):
            matched.append(spec)
    return matched


def _unique_contract_name(specs: List[Dict[str, Any]], name: str) -> bool:
    group = [item for item in specs if _norm(item.get("contract")) == name and item.get("origin") != "static_source"]
    addresses = {_norm(item.get("address")) for item in group if _norm(item.get("address"))}
    benches = {_norm(item.get("bench_contract_id")) for item in group if _norm(item.get("bench_contract_id"))}
    return len(addresses) <= 1 and len(benches) <= 1


SPECIFICITY = {
    "allowance_not_consumed": 0,
    "transfer_gate_halt": 1,
    "residual_privilege_after_ownership_transfer": 2,
    "privileged_mint_or_burn": 3,
    "arithmetic_accounting_invariant": 4,
    "critical_parameter_abuse": 5,
    "initialization_takeover": 6,
    "long_list_out_of_gas": 7,
    "asset_flow_redirection": 8,
    "repeat_claim_no_reset": 9,
    "unchecked_external_call_effect": 10,
    "lock_pause_blacklist_bypass": 11,
    "access_control_state_change": 12,
}


def primary_spec(specs):
    if not specs:
        return None
    preferred = [item for item in specs if item.get("origin") in {"reviewed_finding", "paper_table", "labeled_benchmark"} and item.get("oracle_family")]
    pool = preferred or list(specs)

    def rank(item):
        return (SPECIFICITY.get(str(item.get("oracle_family") or ""), 99), str(item.get("id") or ""))

    return sorted(pool, key=rank)[0]


def to_audit_spec(spec: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "oracle_family": spec.get("oracle_family") or "",
        "normalized_type": spec.get("normalized_type") or spec.get("oracle_family") or "",
        "finding_title": spec.get("finding_title") or "",
        "affected_function": spec.get("affected_function") or "",
        "affected_variable": spec.get("affected_variable") or "",
        "l1_condition_text": spec.get("l1_condition") or spec.get("entry_checkpoint") or "",
        "l2_condition_text": spec.get("l2_condition") or " ".join(spec.get("state2_order") or []),
        "l3_condition_text": spec.get("l3_condition") or " ".join(
            item if isinstance(item, str) else " ".join(item) for item in (spec.get("state3_order") or [])
        ),
        "required_trace_evidence": spec.get("required_trace_evidence") or spec.get("identity") or "",
        "bench_contract_id": spec.get("bench_contract_id") or spec.get("id") or spec.get("uid") or "",
    }
