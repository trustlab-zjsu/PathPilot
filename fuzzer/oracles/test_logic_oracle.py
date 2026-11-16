# -*- coding: utf-8 -*-
from fuzzer.oracles.evaluate import evaluate_trace


def _call(name, sender, tx, success=True, amount=None, args=None, to=""):
    return {
        "event_type": "function_call",
        "function": name,
        "sender": sender,
        "tx_index": tx,
        "success": success,
        "reverted": not success,
        "amount": amount,
        "args": args if args is not None else {},
        "to": to,
        "sequence_id": "s",
    }


def _end(tx, success=True, error=""):
    return {
        "event_type": "tx_end",
        "tx_index": tx,
        "success": success,
        "reverted": not success,
        "error": error,
        "sequence_id": "s",
    }


def _store(tx, variable, new, old=0):
    return {
        "event_type": "sstore",
        "tx_index": tx,
        "variable_name": variable,
        "old_value": old,
        "new_value": new,
        "sequence_id": "s",
    }


ATTACKER = "0x" + "11" * 20
OWNER = "0x" + "22" * 20
NEW = "0x" + "33" * 20
VICTIM = "0x" + "44" * 20


def test_transfer_gate_requires_later_revert_not_success():
    spec = {"oracle_family": "transfer_gate_halt", "affected_function": "setTrading", "affected_variable": "tradingOpen"}
    halt = [
        _call("setTrading", OWNER, 0),
        _end(0, True),
        _store(0, "tradingOpen", 0),
        _call("transfer", ATTACKER, 1, success=False),
        _end(1, False, "revert"),
    ]
    assert evaluate_trace(halt, spec)["level"] == "L3"
    bypass_shaped = [
        _call("setTrading", OWNER, 0),
        _end(0, True),
        _store(0, "tradingOpen", 0),
        _call("transfer", ATTACKER, 1, success=True),
        _end(1, True),
    ]
    assert evaluate_trace(bypass_shaped, spec)["level"] != "L3"


def test_lock_bypass_requires_success_not_revert():
    spec = {"oracle_family": "lock_pause_blacklist_bypass", "affected_function": "transfer", "affected_variable": "paused"}
    success = [
        _call("pause", OWNER, 0),
        _store(0, "paused", 1),
        _end(0, True),
        _call("transfer", ATTACKER, 1, success=True),
        _end(1, True),
    ]
    assert evaluate_trace(success, spec)["level"] == "L3"
    halted = [
        _call("pause", OWNER, 0),
        _store(0, "paused", 1),
        _end(0, True),
        _call("transfer", ATTACKER, 1, success=False),
        _end(1, False),
    ]
    assert evaluate_trace(halted, spec)["level"] != "L3"


def test_parameter_abuse_confirms_on_over_cap_write():
    spec = {"oracle_family": "critical_parameter_abuse", "affected_function": "setFee", "affected_variable": "fee", "cap": 1000}
    events = [
        _call("setFee", OWNER, 0),
        _end(0, True),
        _store(0, "fee", 5000, 0),
    ]
    result = evaluate_trace(events, spec)
    assert result["l3"] is True
    normal = [
        _call("setFee", OWNER, 0),
        _end(0, True),
        _store(0, "fee", 10, 0),
    ]
    assert evaluate_trace(normal, spec)["l3"] is False


def test_allowance_reuse_needs_same_pair():
    spec = {"oracle_family": "allowance_not_consumed", "affected_function": "transferFrom", "affected_variable": "allowance"}
    reused = [
        _call("transferFrom", ATTACKER, 0, amount=5, args={"from": VICTIM, "spender": ATTACKER}),
        _end(0, True),
        _call("transferFrom", ATTACKER, 1, amount=5, args={"from": VICTIM, "spender": ATTACKER}),
        _end(1, True),
    ]
    reused[0]["owner"] = VICTIM
    reused[0]["spender"] = ATTACKER
    reused[2]["owner"] = VICTIM
    reused[2]["spender"] = ATTACKER
    assert evaluate_trace(reused, spec)["l3"] is True
    spent = [
        _call("transferFrom", ATTACKER, 0, amount=5),
        _end(0, True),
        _store(0, "allowance", 0, 5),
    ]
    assert evaluate_trace(spent, spec)["l3"] is False


def test_mint_confirms_on_supply_change_not_unexpected_sender():
    spec = {"oracle_family": "privileged_mint_or_burn", "affected_function": "mint", "privileged_senders": [OWNER]}
    events = [
        _call("mint", OWNER, 0, amount=10),
        _end(0, True),
        _store(0, "totalSupply", 10, 0),
    ]
    assert evaluate_trace(events, spec)["level"] == "L3"


def test_residual_identity():
    spec = {"oracle_family": "residual_privilege_after_ownership_transfer", "affected_function": "transferOwnership"}
    events = [
        _call("transferOwnership", OWNER, 0, args=[NEW]),
        _end(0, True),
        _call("setFee", NEW, 1, success=False),
        _end(1, False),
        _call("setFee", OWNER, 2, success=True),
        _end(2, True),
    ]
    result = evaluate_trace(events, spec)
    assert result["l3"] is True
    assert result["identity_ok"] is True


def test_accounting_mismatch_not_plain_mint():
    spec = {"oracle_family": "arithmetic_accounting_invariant", "affected_function": "burn"}
    plain = [
        _call("burn", OWNER, 0),
        _end(0, True),
        _store(0, "balance", 1, 2),
    ]
    assert evaluate_trace(plain, spec)["l3"] is False
    mismatch = plain + [{"event_type": "invariant_violation", "tx_index": 0, "sequence_id": "s", "mismatch": True}]
    assert evaluate_trace(mismatch, spec)["l3"] is True


def test_writeback_sources_cover_labeled_and_paper():
    import pytest
    from fuzzer.oracles.catalog import match_specs, primary_spec
    from fuzzer.oracles.writeback_sources import (
        CLEAN100_SPECS,
        PAPER_TABLE,
        PAPER_TABLE_FALLBACKS,
        labeled_specs,
        parse_paper_rows,
    )

    if not CLEAN100_SPECS.is_file() or not any(
        path.is_file() for path in (PAPER_TABLE,) + PAPER_TABLE_FALLBACKS
    ):
        pytest.skip("optional benchmark and manuscript inputs are not included in the public source release")

    labeled = labeled_specs()
    assert len(labeled) == 100
    assert {item["oracle_family"] for item in labeled} <= {
        "access_control_state_change",
        "arithmetic_accounting_invariant",
        "asset_flow_redirection",
        "critical_parameter_abuse",
        "initialization_takeover",
        "lock_pause_blacklist_bypass",
        "repeat_claim_no_reset",
        "unchecked_external_call_effect",
    }
    paper = parse_paper_rows()
    pitbull = [item for item in paper if item["contract"] == "Pitbull"]
    assert {item["oracle_family"] for item in pitbull} == {"critical_parameter_abuse", "transfer_gate_halt"}
    assert pitbull[0]["address"].lower() == "0xa57ac35ce91ee92caefaa8dc04140c8e232c2e50"
    assert all(len(item["address"]) == 42 for item in paper)
    catalog = {"specs": labeled + [
        {
            "contract": "Pitbull",
            "address": "0xa57ac35ce91ee92caefaa8dc04140c8e232c2e50",
            "oracle_family": "transfer_gate_halt",
            "origin": "paper_table",
            "source": "Pitbull.sol",
            "source_aliases": ["Pitbull.sol"],
        }
    ]}
    by_address = match_specs(catalog, address="0xA57AC35CE91EE92CAEFAA8DC04140C8E232C2E50")
    assert by_address and by_address[0]["oracle_family"] == "transfer_gate_halt"
    sample = labeled[0]
    by_source = match_specs(catalog, source_path=sample["source"])
    assert sample["id"] in {item["id"] for item in by_source}
    by_bench = match_specs(catalog, contract_name=sample["bench_contract_id"])
    assert primary_spec(by_bench)["origin"] == "labeled_benchmark"


if __name__ == "__main__":
    test_transfer_gate_requires_later_revert_not_success()
    test_lock_bypass_requires_success_not_revert()
    test_parameter_abuse_confirms_on_over_cap_write()
    test_allowance_reuse_needs_same_pair()
    test_mint_confirms_on_supply_change_not_unexpected_sender()
    test_residual_identity()
    test_accounting_mismatch_not_plain_mint()
    test_writeback_sources_cover_labeled_and_paper()
    print("ok")

