"""Article-aligned Runtime-VPPR, Trace-VPPR, and VSPC calculations.

The three metrics intentionally accept plain Python values so that they can be
used with live runtime state as well as exported traces.  Runtime-VPPR is the
original in-fuzzer, deduplicated checkpoint-focus statistic.  Trace-VPPR is
computed only from State 1 sequences and macro-averaged over targets.  VSPC
uses the longest valid ordered prefix of each sequence and takes the maximum
weighted progress over sequences.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple


_SEQUENCE_KEYS = ("checkpoints", "covered_checkpoints", "checkpoint_hits", "events", "trace", "function_names")
_STATE_KEYS = ("state", "validation_state", "state_level", "best_level", "oracle_level", "level")


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _checkpoint_id(value: Any) -> Optional[str]:
    if isinstance(value, Mapping):
        for key in ("id", "checkpoint", "name", "key", "event", "function"):
            if value.get(key) not in (None, ""):
                return _text(value[key])
        return None
    text = _text(value)
    return text or None


def _checkpoint_ids(values: Any) -> List[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes, Mapping)):
        values = [values]
    try:
        iterator = iter(values)
    except TypeError:
        return []
    result: List[str] = []
    for value in iterator:
        item = _checkpoint_id(value)
        if item:
            result.append(item)
    return result


def _reference_ids(reference_checkpoints: Any) -> List[str]:
    """Normalize an ordered reference VTP checkpoint list.

    A mapping is treated as ``checkpoint -> weight``.  This is useful for
    callers that keep weights separately, while a list of checkpoint records
    can carry an explicit ``id``/``name`` field.
    """
    if isinstance(reference_checkpoints, Mapping):
        return [_text(key) for key in reference_checkpoints if _text(key)]
    return _checkpoint_ids(reference_checkpoints)


def _weights(reference_checkpoints: Any, weights: Any = None) -> List[float]:
    ids = _reference_ids(reference_checkpoints)
    if weights is None and isinstance(reference_checkpoints, Mapping):
        weights = list(reference_checkpoints.values())
    if isinstance(weights, Mapping):
        result = []
        for checkpoint in ids:
            try:
                value = float(weights.get(checkpoint, 1.0))
            except (TypeError, ValueError):
                value = 1.0
            result.append(value if value > 0.0 else 1.0)
        return result
    if weights is None:
        return [1.0] * len(ids)
    try:
        values = list(weights)
    except TypeError:
        values = []
    result = []
    for index in range(len(ids)):
        try:
            value = float(values[index])
        except (IndexError, TypeError, ValueError):
            value = 1.0
        result.append(value if value > 0.0 else 1.0)
    return result


def _sequence_checkpoints(sequence: Any, checkpoint_extractor: Optional[Callable[[Any], Any]] = None) -> List[str]:
    if checkpoint_extractor is not None:
        try:
            return _checkpoint_ids(checkpoint_extractor(sequence))
        except Exception:
            return []
    if isinstance(sequence, Mapping):
        for key in _SEQUENCE_KEYS:
            if key in sequence and sequence[key] is not None:
                return _checkpoint_ids(sequence[key])
        return []
    return _checkpoint_ids(sequence)


def _is_state_one(sequence: Any, state1_predicate: Optional[Callable[[Any], bool]] = None) -> bool:
    if state1_predicate is not None:
        try:
            return bool(state1_predicate(sequence))
        except Exception:
            return False
    if not isinstance(sequence, Mapping):
        return False
    for key in _STATE_KEYS:
        if key not in sequence:
            continue
        value = sequence.get(key)
        if isinstance(value, bool):
            return value
        text = _text(value).lower().replace("_", " ").replace("-", " ")
        if text in {"1", "state 1", "state1", "l1", "level 1", "evidence trigger"}:
            return True
        if text in {"0", "state 0", "state0", "none", "no entry"}:
            return False
    return False


def runtime_vppr(target_checkpoints: Any, hit_checkpoints: Any) -> float:
    """Return the original runtime deduplicated checkpoint-focus ratio.

    The numerator is the number of distinct observed checkpoints that belong
    to the reference VTP; the denominator is the number of distinct observed
    checkpoints.  A run with no observed checkpoints contributes ``0.0``.
    """
    target: Set[str] = set(_reference_ids(target_checkpoints))
    observed: Set[str] = set(_checkpoint_ids(hit_checkpoints))
    return float(len(target.intersection(observed))) / float(len(observed)) if observed else 0.0


def trace_vppr_for_target(
    sequences: Iterable[Any],
    reference_checkpoints: Any,
    *,
    state1_predicate: Optional[Callable[[Any], bool]] = None,
    checkpoint_extractor: Optional[Callable[[Any], Any]] = None,
) -> float:
    """Compute Eq. (Trace-VPPR) for one target.

    Only sequences classified as State 1 are included.  For each included
    sequence, ``q`` is the count of distinct reference checkpoints observed in
    that sequence.  No State 1 sequence or an empty reference path yields zero.
    """
    reference = _reference_ids(reference_checkpoints)
    reference_set = set(reference)
    if not reference_set:
        return 0.0
    total_sequences = 0
    covered_sum = 0
    try:
        iterator = iter(sequences)
    except TypeError:
        return 0.0
    for sequence in iterator:
        if not _is_state_one(sequence, state1_predicate):
            continue
        total_sequences += 1
        covered_sum += len(set(_sequence_checkpoints(sequence, checkpoint_extractor)).intersection(reference_set))
    denominator = len(reference) * total_sequences
    return float(covered_sum) / float(denominator) if denominator else 0.0


def _target_parts(target: Any) -> Tuple[Iterable[Any], Any]:
    if isinstance(target, Mapping):
        sequences = target.get("sequences", target.get("transaction_sequences", target.get("traces", [])))
        reference = target.get("reference_checkpoints", target.get("checkpoints", target.get("vtp", [])))
        return sequences or [], reference or []
    return [], []


def trace_vppr_macro_average(
    targets: Any,
    *,
    state1_predicate: Optional[Callable[[Any], bool]] = None,
    checkpoint_extractor: Optional[Callable[[Any], Any]] = None,
) -> float:
    """Macro-average target-level Trace-VPPR with zero-filled invalid targets.

    ``targets`` may be a sequence of target records or a mapping from target
    id to target record.  Each record contains ``sequences`` and
    ``reference_checkpoints`` (aliases are accepted by ``_target_parts``).
    """
    if isinstance(targets, Mapping):
        records = list(targets.values())
    else:
        try:
            records = list(targets)
        except TypeError:
            records = []
    if not records:
        return 0.0
    scores = []
    for target in records:
        sequences, reference = _target_parts(target)
        scores.append(trace_vppr_for_target(
            sequences,
            reference,
            state1_predicate=state1_predicate,
            checkpoint_extractor=checkpoint_extractor,
        ))
    return sum(scores) / float(len(scores))


def vspc_for_sequence(sequence: Any, reference_checkpoints: Any, weights: Any = None, *, checkpoint_extractor: Optional[Callable[[Any], Any]] = None) -> float:
    """Compute weighted longest valid ordered-prefix progress for one sequence."""
    reference = _reference_ids(reference_checkpoints)
    if not reference:
        return 0.0
    sequence_ids = _sequence_checkpoints(sequence, checkpoint_extractor)
    if not sequence_ids:
        return 0.0
    matched = 0
    for observed in sequence_ids:
        if matched < len(reference) and observed == reference[matched]:
            matched += 1
    checkpoint_weights = _weights(reference_checkpoints, weights)
    denominator = sum(checkpoint_weights)
    return sum(checkpoint_weights[:matched]) / denominator if denominator > 0.0 else 0.0


def vspc_for_run(
    sequences: Iterable[Any],
    reference_checkpoints: Any,
    weights: Any = None,
    *,
    checkpoint_extractor: Optional[Callable[[Any], Any]] = None,
) -> float:
    """Compute Eq. (VSPC), taking the maximum score over all sequences."""
    try:
        iterator = iter(sequences)
    except TypeError:
        return 0.0
    best = 0.0
    for sequence in iterator:
        best = max(best, vspc_for_sequence(
            sequence,
            reference_checkpoints,
            weights,
            checkpoint_extractor=checkpoint_extractor,
        ))
    return best
