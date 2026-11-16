# -*- coding: utf-8 -*-

"""Typed append-only runtime evidence store shared by runtime components."""

import json
import os
from typing import Any, Dict, Iterable, List, Optional


class EvidencePool:
    """Persist heterogeneous evidence with an explicit ``evidence_type`` tag.

    Existing component-specific artifacts remain available for compatibility;
    this file is the canonical cross-component evidence stream.
    """

    def __init__(self, output_dir: str):
        self.output_dir = os.path.abspath(output_dir) if output_dir else ""
        self.path = os.path.join(self.output_dir, "evidence_pool.jsonl") if self.output_dir else ""

    def reset(self) -> bool:
        if not self.path:
            return False
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            with open(self.path, "w", encoding="utf-8"):
                pass
            return True
        except Exception:
            return False

    def append(self, evidence_type: str, record: Dict[str, Any]) -> bool:
        if not self.path or not isinstance(record, dict):
            return False
        payload = dict(record)
        payload["evidence_type"] = str(evidence_type or "unknown")
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
            return True
        except Exception:
            return False

    def append_many(self, evidence_type: str, records: Iterable[Dict[str, Any]]) -> int:
        return sum(1 for record in records if self.append(evidence_type, record))

    @staticmethod
    def read(path: Optional[str], evidence_type: Optional[str] = None) -> List[Dict[str, Any]]:
        if not path or not os.path.exists(path):
            return []
        records: List[Dict[str, Any]] = []
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        payload = json.loads(line.strip())
                    except Exception:
                        continue
                    if not isinstance(payload, dict):
                        continue
                    if evidence_type and payload.get("evidence_type") != evidence_type:
                        continue
                    records.append(payload)
        except Exception:
            return []
        return records

    @staticmethod
    def gei_shortlist_payload(path: Optional[str], limit: int = 20) -> Dict[str, Any]:
        ranked = EvidencePool.read(path, "gei_topk_candidate")
        if ranked:
            latest_by_rank = {int(item.get("rank") or 0): item for item in ranked}
            shortlist = [latest_by_rank[key] for key in sorted(latest_by_rank) if key > 0]
        else:
            candidates = EvidencePool.read(path, "gei_scored_observation")
            best_by_path: Dict[Any, Dict[str, Any]] = {}
            for item in candidates:
                if str(item.get("tier") or "low") not in ("high", "medium"):
                    continue
                signature = tuple(str(value) for value in item.get("suggested_path") or [])
                current = best_by_path.get(signature)
                key = (int(item.get("quality_score") or 0), float(item.get("coverage_delta") or 0.0))
                current_key = (
                    int(current.get("quality_score") or 0),
                    float(current.get("coverage_delta") or 0.0),
                ) if current else None
                if current is None or key > current_key:
                    best_by_path[signature] = item
            shortlist = sorted(
                best_by_path.values(),
                key=lambda item: (
                    int(item.get("quality_score") or 0),
                    float(item.get("coverage_delta") or 0.0),
                ),
                reverse=True,
            )
        normalized = []
        for item in shortlist[: max(0, int(limit))]:
            normalized.append(
                {
                    "sequence_id": str(item.get("sequence_id") or ""),
                    "suggested_path": [str(value) for value in item.get("suggested_path") or []],
                    "reason": str(item.get("reason") or "unknown"),
                    "quality_score": int(item.get("quality_score") or 0),
                    "tier": str(item.get("tier") or "low"),
                    "signals": dict(item.get("signals") or {}),
                }
            )
        return {
            "summary": {"shortlist_count": len(normalized)},
            "shortlist": normalized,
        }
