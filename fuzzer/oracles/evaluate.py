# -*- coding: utf-8 -*-
"""Sequence-level confirmation oracle for the thirteen PathPilot families.

Reaching a function is not confirmation. State 2 and State 3 checkpoints must
occur in the required order inside one transaction sequence. An over-cap or
zero-denominator write can confirm critical parameter abuse without a later
business path. Transfer-gate halt confirms a later revert; lock, pause, or
blacklist bypass confirms that the restricted operation still succeeds.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from fuzzer.oracles.families import FAMILY_STATES, family_checkpoints


def _text(value: Any) -> str:
    if value in (None, ""):
        return ""
    return str(value).strip()


def _lower(value: Any) -> str:
    return _text(value).lower()


def _addr(value: Any) -> str:
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, int):
        return "0x" + format(value & ((1 << 160) - 1), "040x")
    text = _lower(value)
    if text.startswith("0x") and len(text) == 42 and all(char in "0123456789abcdef" for char in text[2:]):
        return text
    if text.isdigit():
        return "0x" + format(int(text) & ((1 << 160) - 1), "040x")
    return ""


def _as_int(value: Any) -> Optional[int]:
    if value is None or value == "" or isinstance(value, bool):
        return int(value) if isinstance(value, bool) else None
    if isinstance(value, int):
        return value
    text = _text(value)
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except Exception:
        return None


def _has_token(text: str, tokens: Iterable[str]) -> bool:
    hay = text.lower()
    return any(token in hay for token in tokens)


def normalize_events(events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for index, raw in enumerate(events or []):
        if not isinstance(raw, dict):
            continue
        args = raw.get("args") if isinstance(raw.get("args"), (dict, list)) else {}
        spender = _addr(raw.get("spender") or (args.get("spender") if isinstance(args, dict) else ""))
        owner = _addr(
            raw.get("owner")
            or raw.get("from_addr")
            or raw.get("token_from")
            or (args.get("from") if isinstance(args, dict) else "")
        )
        item = {
            "event_index": index,
            "event_type": _lower(raw.get("event_type")),
            "function": _text(raw.get("function") or raw.get("function_name")),
            "sender": _addr(raw.get("sender") or raw.get("from")),
            "success": raw.get("success"),
            "reverted": bool(raw.get("reverted") or raw.get("revert")),
            "error": _text(raw.get("error") or raw.get("revert_reason")),
            "tx_index": raw.get("tx_index", raw.get("local_tx_index")),
            "sequence_id": _text(raw.get("sequence_id")) or "seq",
            "variable": _lower(raw.get("variable_name") or raw.get("variable") or raw.get("slot")),
            "old_value": raw.get("old_value"),
            "new_value": raw.get("new_value"),
            "to": _addr(raw.get("to")),
            "amount": raw.get("amount"),
            "args": args,
            "spender": spender,
            "owner": owner,
            "mismatch": raw.get("mismatch") is True or _lower(raw.get("event_type")) in {"invariant_violation", "supply_mismatch"},
        }
        normalized.append(item)
    by_tx: Dict[Tuple[str, Any], Dict[str, Any]] = {}
    for item in normalized:
        if item["event_type"] in {"tx_end", "revert"}:
            by_tx[(item["sequence_id"], item["tx_index"])] = item
    for item in normalized:
        end = by_tx.get((item["sequence_id"], item["tx_index"]))
        if item["event_type"] == "function_call" and end is not None:
            item["tx_success"] = end.get("success") is True and not end.get("reverted")
            item["tx_reverted"] = bool(end.get("reverted") or end.get("success") is False)
            item["tx_error"] = end.get("error") or ""
        elif item["event_type"] == "function_call":
            item["tx_success"] = item.get("success") is True
            item["tx_reverted"] = bool(item.get("reverted") or item.get("success") is False)
            item["tx_error"] = item.get("error") or ""
        else:
            item["tx_success"] = item.get("success") is True
            item["tx_reverted"] = bool(item.get("reverted"))
            item["tx_error"] = item.get("error") or ""
    return normalized


def _fn(event: Dict[str, Any]) -> str:
    return _lower(event.get("function"))


def _call(event: Dict[str, Any]) -> bool:
    return event.get("event_type") == "function_call"


def _success(event: Dict[str, Any]) -> bool:
    if event.get("event_type") == "tx_end":
        return event.get("success") is True and not event.get("reverted")
    return bool(event.get("tx_success") or event.get("success") is True) and not event.get("tx_reverted") and not event.get("reverted")


def _reverted(event: Dict[str, Any]) -> bool:
    if event.get("event_type") == "revert":
        return True
    if event.get("event_type") == "tx_end":
        return bool(event.get("reverted") or event.get("success") is False)
    return bool(event.get("tx_reverted") or event.get("reverted"))


def _affected(spec: Dict[str, Any]) -> str:
    return _lower(spec.get("affected_function"))


def _variable(spec: Dict[str, Any]) -> str:
    return _lower(spec.get("affected_variable"))


def _named_call(event: Dict[str, Any], spec: Dict[str, Any], tokens: Sequence[str]) -> bool:
    if not _call(event):
        return False
    target = _affected(spec)
    name = _fn(event)
    if target and target in name:
        return True
    return _has_token(name, tokens)


def _sstore(event: Dict[str, Any]) -> bool:
    return event.get("event_type") in {"sstore", "state_write"}


def _var_hit(event: Dict[str, Any], spec: Dict[str, Any], tokens: Sequence[str]) -> bool:
    variable = _variable(spec)
    hay = event.get("variable") or ""
    if variable and variable in hay:
        return True
    return _has_token(hay, tokens)


def _unexpected(event: Dict[str, Any], spec: Dict[str, Any]) -> bool:
    sender = event.get("sender") or ""
    privileged = {_addr(item) for item in (spec.get("privileged_senders") or []) if _addr(item)}
    if privileged:
        return bool(sender) and sender not in privileged
    if event.get("raw_unexpected") or (isinstance(event.get("args"), dict) and event["args"].get("unexpected_sender")):
        return True
    return bool(sender) and sender != "0x" + "0" * 40


def _is_address_value(value: Any) -> bool:
    address = _addr(value)
    if not address:
        return False
    return address not in {"0x" + "0" * 40, "0x" + "0" * 39 + "1"}


def _amount_positive(event: Dict[str, Any]) -> bool:
    amount = _as_int(event.get("amount"))
    if amount is None and isinstance(event.get("args"), dict):
        for key in ("amount", "value", "wad", "_amount", "a0"):
            amount = _as_int(event["args"].get(key))
            if amount is not None:
                break
    if amount is None and isinstance(event.get("args"), list) and event["args"]:
        amount = _as_int(event["args"][0])
    return amount is not None and amount > 0


def _out_of_gas(event: Dict[str, Any]) -> bool:
    text = _lower(event.get("error") or event.get("tx_error"))
    return "out of gas" in text or "outofgas" in text


def _long_list(event: Dict[str, Any], spec: Dict[str, Any]) -> bool:
    minimum = int(spec.get("long_list_min") or 20)
    args = event.get("args")
    if isinstance(args, list) and len(args) >= minimum:
        return True
    if isinstance(args, dict):
        for value in args.values():
            if isinstance(value, list) and len(value) >= minimum:
                return True
    length = _as_int(event.get("amount"))
    return length is not None and length >= minimum


def _same_pair(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    left_from = left.get("owner") or left.get("sender")
    right_from = right.get("owner") or right.get("sender")
    left_spender = left.get("spender") or left.get("sender")
    right_spender = right.get("spender") or right.get("sender")
    return bool(left_from and right_from and left_spender and right_spender and left_from == right_from and left_spender == right_spender)


def _match_checkpoint(name: str, event: Dict[str, Any], spec: Dict[str, Any], chosen: Dict[str, Dict[str, Any]]) -> bool:
    family = _text(spec.get("oracle_family"))
    if name == "protected_function_reached":
        return _named_call(event, spec, ("set", "owner", "admin", "mint", "withdraw", "grant", "role", "pause"))
    if name == "unexpected_sender_observed":
        return _call(event) and _unexpected(event, spec)
    if name == "guarded_region_or_tx_success":
        return _call(event) and _success(event)
    if name == "critical_state_written":
        return _sstore(event) and _var_hit(event, spec, ("owner", "admin", "role", "balance", "allowance", "fee"))
    if name == "accounting_path_reached":
        return _named_call(event, spec, ("mint", "burn", "transfer", "stake", "rebase", "reflect", "deposit", "withdraw"))
    if name == "precision_supply_or_burn_operation_observed":
        return _call(event) and _has_token(_fn(event), ("mint", "burn", "transfer", "rebase", "reflect", "stake"))
    if name == "balance_or_supply_change_observed":
        return event.get("event_type") in {"balance_change", "token_transfer"} or (
            _sstore(event) and _var_hit(event, spec, ("balance", "supply", "total", "stake", "rowned", "towned"))
        )
    if name == "supply_balance_or_unit_mismatch_observed":
        if event.get("event_type") in {"invariant_violation", "supply_mismatch"} or event.get("mismatch") is True:
            return True
        return _sstore(event) and bool(event.get("mismatch"))
    if name == "critical_setter_reached":
        return _named_call(event, spec, ("set", "wallet", "receiver", "treasury", "fee", "recipient", "marketing"))
    if name == "receiver_or_fee_state_written":
        return _sstore(event) and _is_address_value(event.get("new_value")) and _var_hit(
            event, spec, ("wallet", "receiver", "treasury", "fee", "recipient", "marketing", "router")
        )
    if name == "dependent_business_path_executed":
        return _named_call(event, spec, ("transfer", "withdraw", "swap", "claim", "sell", "buy", "distribute")) and _success(event)
    if name == "asset_flow_sink_touched":
        return event.get("event_type") == "external_call" or _has_token(_fn(event), ("transfer", "swap", "withdraw", "send"))
    if name == "transfer_or_balance_change_observed":
        return event.get("event_type") in {"token_transfer", "balance_change", "native_transfer"}
    if name == "funds_flow_to_changed_or_unexpected_receiver":
        written = chosen.get("receiver_or_fee_state_written") or {}
        target = _addr(written.get("new_value"))
        recipient = event.get("to") or _addr(event.get("new_value"))
        return event.get("event_type") in {"token_transfer", "native_transfer", "balance_change"} and bool(target) and recipient == target
    if name == "parameter_setter_or_dependent_path_reached":
        return _named_call(event, spec, ("set", "fee", "tax", "rate", "limit", "cap", "denominator", "transfer", "swap"))
    if name == "setter_succeeded":
        return _named_call(event, spec, ("set", "update", "config", "fee", "tax", "rate")) and _success(event)
    if name == "unbounded_or_zero_denominator_value_observed":
        if not _sstore(event):
            return False
        new_value = _as_int(event.get("new_value"))
        cap = _as_int(spec.get("cap"))
        variable = event.get("variable") or ""
        if new_value is None:
            return False
        if cap is not None and new_value > cap:
            return True
        if new_value == 0 and _has_token(variable, ("denom", "divider", "base", "fee", "tax")):
            return True
        return new_value >= 10 ** 18 and _has_token(variable, ("fee", "tax", "rate", "share", "cap", "limit"))
    if name == "over_cap_write_or_abnormal_effect":
        if _match_checkpoint("unbounded_or_zero_denominator_value_observed", event, spec, chosen):
            return True
        setter = chosen.get("unbounded_or_zero_denominator_value_observed")
        if not setter or event.get("event_index", -1) <= setter.get("event_index", -1):
            return False
        return _out_of_gas(event) or "div" in _lower(event.get("error")) or event.get("event_type") in {"balance_change", "token_transfer", "invariant_violation"}
    if name == "init_function_reached":
        return _named_call(event, spec, ("initialize", "init", "setup"))
    if name == "init_tx_success":
        return _named_call(event, spec, ("initialize", "init", "setup")) and _success(event)
    if name == "owner_admin_role_state_written":
        return _sstore(event) and _var_hit(event, spec, ("owner", "admin", "role", "operator", "governor"))
    if name == "privileged_effect_after_takeover":
        written = chosen.get("owner_admin_role_state_written") or {}
        new_owner = _addr(written.get("new_value"))
        return _call(event) and _success(event) and bool(new_owner) and event.get("sender") == new_owner and event.get("event_index", -1) > written.get("event_index", -1)
    if name == "restricted_state_observed":
        return _named_call(event, spec, ("pause", "blacklist", "lock", "ban", "block", "freeze")) or (
            _sstore(event) and _var_hit(event, spec, ("pause", "black", "lock", "ban", "freeze"))
        )
    if name == "restriction_active":
        return _sstore(event) and _var_hit(event, spec, ("pause", "black", "lock", "ban", "freeze", "restrict")) and _as_int(event.get("new_value")) not in (None, 0)
    if name == "restricted_operation_called":
        return _named_call(event, spec, ("transfer", "sell", "withdraw", "burn", "swap"))
    if name == "restricted_operation_success":
        entry = chosen.get("restricted_operation_called") or {}
        return _call(event) and _success(event) and _fn(event) == _fn(entry) and event.get("tx_index") == entry.get("tx_index")
    if name == "gate_setter_or_transfer_reached":
        return _named_call(event, spec, ("set", "transfer", "trading", "bot", "black", "pause", "max"))
    if name == "gate_setter_succeeded":
        return _named_call(event, spec, ("set", "enable", "disable", "black", "bot", "trading", "pause", "max", "gate")) and _success(event)
    if name == "restriction_state_written":
        return _sstore(event) and _var_hit(event, spec, ("trading", "bot", "black", "pause", "max", "gate", "limit", "cooldown", "restrict", "fee"))
    if name == "later_gated_transfer_reverted":
        written = chosen.get("restriction_state_written") or {}
        if not _named_call(event, spec, ("transfer", "transferfrom")) or not _reverted(event):
            return False
        if event.get("event_index", -1) <= written.get("event_index", -1):
            return False
        written_value = written.get("new_value")
        if _is_address_value(written_value):
            target = _addr(written_value)
            return event.get("sender") == target or event.get("to") == target
        return True
    if name == "claim_like_function_reached":
        return _named_call(event, spec, ("claim", "harvest", "getreward", "reward"))
    if name == "setup_or_balance_preparation_observed":
        return _named_call(event, spec, ("deposit", "stake", "approve", "mint", "fund")) and _success(event)
    if name == "first_claim_success":
        return _named_call(event, spec, ("claim", "harvest", "getreward")) and _success(event)
    if name == "second_claim_attempted":
        first = chosen.get("first_claim_success") or {}
        return _named_call(event, spec, ("claim", "harvest", "getreward")) and event.get("event_index", -1) > first.get("event_index", -1)
    if name == "second_claim_success_or_no_expected_revert":
        previous = chosen.get("second_claim_attempted") or {}
        return _call(event) and _success(event) and event.get("tx_index") == previous.get("tx_index") and _fn(event) == _fn(previous)
    if name == "abnormal_balance_or_state_no_reset_observed":
        return event.get("event_type") in {"balance_change", "token_transfer", "invariant_violation"} or (
            _sstore(event) and _var_hit(event, spec, ("claim", "reward", "pending", "harvest"))
        )
    if name == "external_call_reached":
        return event.get("event_type") == "external_call" or _named_call(event, spec, ("call", "execute", "withdraw"))
    if name == "external_call_failed":
        return event.get("event_type") == "external_call" and (event.get("success") is False or event.get("reverted"))
    if name == "parent_tx_did_not_revert":
        failed = chosen.get("external_call_failed") or {}
        return event.get("event_type") == "tx_end" and event.get("success") is True and not event.get("reverted") and event.get("tx_index") == failed.get("tx_index")
    if name == "state_or_asset_effect_after_failed_call":
        failed = chosen.get("external_call_failed") or {}
        return event.get("tx_index") == failed.get("tx_index") and event.get("event_index", -1) > failed.get("event_index", -1) and (
            _sstore(event) or event.get("event_type") in {"balance_change", "token_transfer"}
        )
    if name == "inconsistent_state_observed":
        return _match_checkpoint("state_or_asset_effect_after_failed_call", event, spec, chosen) and (
            _var_hit(event, spec, ("balance", "supply", "debt", "claim", "share", "owed")) or event.get("event_type") == "invariant_violation"
        )
    if name == "mint_or_burn_reached":
        return _named_call(event, spec, ("mint", "burn"))
    if name == "mint_or_burn_succeeded":
        return _named_call(event, spec, ("mint", "burn")) and _success(event)
    if name == "balance_or_supply_changed":
        return event.get("event_type") in {"balance_change", "token_transfer"} or (
            _sstore(event) and _var_hit(event, spec, ("balance", "supply", "total"))
        )
    if name == "transfer_from_reached":
        return _named_call(event, spec, ("transferfrom",))
    if name == "positive_transfer_from_succeeded":
        return _named_call(event, spec, ("transferfrom",)) and _success(event) and _amount_positive(event)
    if name == "allowance_unchanged_or_reused":
        if _sstore(event) and _var_hit(event, spec, ("allowance",)) and event.get("old_value") == event.get("new_value"):
            return True
        first = chosen.get("positive_transfer_from_succeeded") or {}
        return (
            _named_call(event, spec, ("transferfrom",))
            and _success(event)
            and _amount_positive(event)
            and event.get("event_index", -1) > first.get("event_index", -1)
            and _same_pair(first, event)
        )
    if name == "bulk_list_function_reached":
        return _named_call(event, spec, ("airdrop", "multi", "batch", "bulk", "distribute", "setlist", "addlist"))
    if name == "long_address_list_observed":
        return _long_list(event, spec)
    if name == "out_of_gas_revert":
        return _reverted(event) and _out_of_gas(event)
    if name == "ownership_or_setter_reached":
        return _named_call(event, spec, ("transferowner", "transferownership", "renounce", "set"))
    if name == "ownership_transfer_succeeded":
        return _named_call(event, spec, ("transferowner", "transferownership")) and _success(event)
    if name == "new_owner_setter_reverted":
        transfer = chosen.get("ownership_transfer_succeeded") or {}
        new_owner = _addr(transfer.get("new_value") or (transfer.get("args") or {}).get("newOwner") if isinstance(transfer.get("args"), dict) else "")
        if not new_owner and isinstance(transfer.get("args"), list) and transfer["args"]:
            new_owner = _addr(transfer["args"][0])
        return _call(event) and _reverted(event) and bool(new_owner) and event.get("sender") == new_owner and event.get("event_index", -1) > transfer.get("event_index", -1)
    if name == "old_role_setter_succeeded":
        transfer = chosen.get("ownership_transfer_succeeded") or {}
        new_owner = _addr(transfer.get("new_value") or "")
        if not new_owner and isinstance(transfer.get("args"), dict):
            new_owner = _addr(transfer["args"].get("newOwner") or transfer["args"].get("new_owner"))
        if not new_owner and isinstance(transfer.get("args"), list) and transfer["args"]:
            new_owner = _addr(transfer["args"][0])
        return (
            _call(event)
            and _success(event)
            and event.get("event_index", -1) > transfer.get("event_index", -1)
            and bool(event.get("sender"))
            and event.get("sender") != new_owner
        )
    return False


def _walk(chain: Sequence[str], events: Sequence[Dict[str, Any]], spec: Dict[str, Any]) -> Tuple[bool, Dict[str, Dict[str, Any]]]:
    chosen: Dict[str, Dict[str, Any]] = {}
    cursor = -1
    last = None
    for name in chain:
        found = None
        if last is not None and _match_checkpoint(name, last, spec, chosen):
            found = last
        else:
            for event in events:
                if event.get("event_index", -1) <= cursor:
                    continue
                if _match_checkpoint(name, event, spec, chosen):
                    found = event
                    break
        if found is None:
            return False, chosen
        chosen[name] = found
        last = found
        cursor = int(found.get("event_index") or 0)
    return True, chosen


def _identity_ok(family: str, chosen: Dict[str, Dict[str, Any]]) -> Optional[bool]:
    if family == "asset_flow_redirection":
        written = chosen.get("receiver_or_fee_state_written") or {}
        flow = chosen.get("funds_flow_to_changed_or_unexpected_receiver") or {}
        if not written or not flow:
            return None
        return _addr(written.get("new_value")) == (flow.get("to") or _addr(flow.get("new_value")))
    if family == "initialization_takeover":
        written = chosen.get("owner_admin_role_state_written") or {}
        effect = chosen.get("privileged_effect_after_takeover") or {}
        if not written or not effect:
            return None
        return _addr(written.get("new_value")) == effect.get("sender")
    if family == "transfer_gate_halt":
        written = chosen.get("restriction_state_written") or {}
        later = chosen.get("later_gated_transfer_reverted") or {}
        if not _is_address_value(written.get("new_value")):
            return None
        target = _addr(written.get("new_value"))
        return later.get("sender") == target or later.get("to") == target
    if family == "repeat_claim_no_reset":
        entry = chosen.get("claim_like_function_reached") or {}
        second = chosen.get("second_claim_attempted") or {}
        if not entry or not second:
            return None
        return bool(entry.get("sender")) and entry.get("sender") == second.get("sender")
    if family == "allowance_not_consumed":
        first = chosen.get("positive_transfer_from_succeeded") or {}
        reused = chosen.get("allowance_unchanged_or_reused") or {}
        if reused.get("event_type") in {"sstore", "state_write"}:
            return None
        return _same_pair(first, reused)
    if family == "residual_privilege_after_ownership_transfer":
        transfer = chosen.get("ownership_transfer_succeeded") or {}
        new_owner = ""
        if isinstance(transfer.get("args"), dict):
            new_owner = _addr(transfer["args"].get("newOwner") or transfer["args"].get("new_owner"))
        if not new_owner and isinstance(transfer.get("args"), list) and transfer["args"]:
            new_owner = _addr(transfer["args"][0])
        new_owner = new_owner or _addr(transfer.get("new_value"))
        blocked = chosen.get("new_owner_setter_reverted") or {}
        old = chosen.get("old_role_setter_succeeded") or {}
        if not new_owner or not blocked or not old:
            return False
        return old.get("sender") != new_owner and blocked.get("sender") == new_owner
    return None


def _level_from_flags(l1: bool, l2: bool, l3: bool) -> str:
    if l3:
        return "L3"
    if l2:
        return "L2"
    if l1:
        return "L1"
    return "none"


def evaluate_sequence(events: Sequence[Dict[str, Any]], spec: Dict[str, Any]) -> Dict[str, Any]:
    family = _text(spec.get("oracle_family"))
    state = FAMILY_STATES.get(family)
    if not state:
        return {
            "level": "none",
            "l1": False,
            "l2": False,
            "l3": False,
            "oracle_family": family,
            "reason": "unknown_oracle_family",
            "covered": [],
        }
    normalized = list(events)
    entry_name = _text(state.get("entry"))
    l1 = any(_match_checkpoint(entry_name, event, spec, {}) for event in normalized)
    covered = [entry_name] if l1 else []
    s2_ok, s2_chosen = _walk(list(state.get("s2") or []), normalized, spec)
    if s2_ok:
        covered = list(s2_chosen.keys())
    l3 = False
    chosen = dict(s2_chosen)
    identity = None
    if state.get("s3_chains"):
        chain_chosen: Dict[str, Dict[str, Any]] = {}
        l3 = True
        for chain in state["s3_chains"]:
            ok, one = _walk(list(chain), normalized, spec)
            if not ok:
                l3 = False
                break
            chain_chosen.update(one)
        if l3:
            chosen = chain_chosen
            covered = list(chosen.keys())
            identity = _identity_ok(family, chosen)
            if identity is False:
                l3 = False
    else:
        s3_ok, s3_chosen = _walk(list(state.get("s3") or []), normalized, spec)
        if s3_ok:
            chosen = s3_chosen
            covered = list(chosen.keys())
            identity = _identity_ok(family, chosen)
            l3 = identity is not False
    if family == "repeat_claim_no_reset" and l3:
        identity = _identity_ok(family, chosen)
        if identity is False:
            l3 = False
    reason = "confirmed" if l3 else "context_matched" if s2_ok else "entry_reached" if l1 else "not_observed"
    return {
        "level": _level_from_flags(l1, s2_ok, l3),
        "l1": l1,
        "l2": s2_ok,
        "l3": l3,
        "oracle_family": family,
        "reason": reason,
        "covered": covered,
        "identity_ok": identity,
        "checkpoints": family_checkpoints(family),
    }


def evaluate_trace(events: Sequence[Dict[str, Any]], spec: Dict[str, Any]) -> Dict[str, Any]:
    normalized = normalize_events(events)
    if not normalized:
        return evaluate_sequence([], spec)
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for event in normalized:
        groups.setdefault(event.get("sequence_id") or "seq", []).append(event)
    best = None
    rank = {"none": 0, "L1": 1, "L2": 2, "L3": 3}
    for group in groups.values():
        result = evaluate_sequence(group, spec)
        if best is None or rank[result["level"]] > rank[best["level"]]:
            best = result
    return best or evaluate_sequence([], spec)
