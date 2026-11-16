"""Bounded buffer for evidence-guided candidates.

Candidates are queued for the normal population path.  The public release
does not execute candidates in a separate preflight environment.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class TCICandidateBuffer:
    def __init__(self, max_size: int = 64, max_per_round: int = 3, **_: Any) -> None:
        self.max_size = max(1, int(max_size or 1))
        self.max_per_round = max(1, int(max_per_round or 1))
        self._items: List[Dict[str, Any]] = []
        self.last_pop_duplicate_count = 0
        self.duplicate_skipped_count = 0

    def add_candidates(self, candidates: List[Dict[str, Any]]) -> int:
        added = 0
        seen = {str(item.get("candidate_id")) for item in self._items if isinstance(item, dict)}
        for candidate in candidates or []:
            if not isinstance(candidate, dict) or not candidate.get("useful"):
                continue
            key = str(candidate.get("candidate_id") or "")
            if not key or key in seen:
                self.duplicate_skipped_count += 1
                continue
            seen.add(key)
            self._items.append(dict(candidate))
            added += 1
        self._items = self._items[-self.max_size:]
        return added

    def pop_for_round(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        count = max(0, int(limit if limit is not None else self.max_per_round))
        selected, self._items = self._items[:count], self._items[count:]
        return selected

    def __len__(self) -> int:
        return len(self._items)


__all__ = ["TCICandidateBuffer"]
