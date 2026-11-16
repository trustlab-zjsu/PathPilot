# -*- coding: utf-8 -*-
"""Build PathPilot oracle specs from the original 100 contracts and later real contracts.

This is a static write-back. It does not launch the fuzzer.
"""

from __future__ import annotations

import json
import re
import sys
import os
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from fuzzer.oracles.families import (
    FAMILY_ORDER,
    FAMILY_STATES,
    REVIEW_FAMILY_MAP,
    UNMAPPED_REVIEW_FAMILIES,
    family_checkpoints,
)
from fuzzer.oracles.writeback_sources import attach_paper_sources, labeled_specs, paper_specs


PATHPILOT_ROOT = Path(__file__).resolve().parents[2]
VULN100_DIR = Path(__file__).resolve().parents[2] / "dataset_contracts" / "vuln100"
REALWORLD_DIR = Path(__file__).resolve().parents[2] / "dataset_contracts" / "realworld"
AUDIT_ORACLE_DIR = Path(os.environ.get("PATHPILOT_AUDIT_ORACLE_DIR", ""))
CATALOG_PATH = Path(__file__).resolve().parent / "catalog" / "logic_oracle_catalog.json"

REVIEW_MODULES = (
    ("batch2_oracles", "BATCH2_FINDINGS"),
    ("batch3_oracles", "BATCH3_FINDINGS"),
    ("batch4_oracles", "BATCH4_FINDINGS"),
    ("batch5_oracles", "BATCH5_FINDINGS"),
    ("batch6_oracles", "BATCH6_FINDINGS"),
    ("batch7_oracles", "BATCH7_FINDINGS"),
    ("original_report_oracles", "ORIGINAL_FINDINGS"),
    ("extra_realworld_oracles", "EXTRA_FINDINGS"),
)

FUNC_RE = re.compile(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.M)
SKIP_DIRS = {"node_modules", "vendor", "openzeppelin", ".git", "__pycache__"}



PAPER_TABLE = Path(os.environ.get("PATHPILOT_PAPER_TABLE", ""))
PAPER_CODE_MAP = {
    "AAI": "arithmetic_accounting_invariant",
    "ANC": "allowance_not_consumed",
    "CPA": "critical_parameter_abuse",
    "LLOG": "long_list_out_of_gas",
    "PMB": "privileged_mint_or_burn",
    "RPO": "residual_privilege_after_ownership_transfer",
    "TG": "transfer_gate_halt",
}


def _paper_specs() -> List[dict]:
    return paper_specs()


def _load_review_rows() -> List[dict]:
    if not AUDIT_ORACLE_DIR.exists():
        return []
    sys.path.insert(0, str(AUDIT_ORACLE_DIR))
    rows: List[dict] = []
    for module_name, attr in REVIEW_MODULES:
        module = __import__(module_name)
        found = list(getattr(module, attr))
        for item in found:
            copied = dict(item)
            copied["review_module"] = module_name
            rows.append(copied)
    return rows


def _functions(source: str) -> List[dict]:
    functions = []
    for match in FUNC_RE.finditer(source):
        name = match.group(1)
        header_end = source.find("{", match.end())
        semi = source.find(";", match.end())
        if header_end < 0 or (0 <= semi < header_end):
            continue
        header = source[match.start():header_end]
        body, end = _brace_body(source, header_end)
        functions.append({"name": name, "header": header, "body": body, "end": end})
    return functions


def _brace_body(source: str, open_brace: int) -> tuple:
    depth = 0
    for index in range(open_brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace + 1:index], index
    return source[open_brace + 1:open_brace + 4000], min(len(source), open_brace + 4000)


def _public(header: str) -> bool:
    lowered = header.lower()
    if "private" in lowered or "internal" in lowered:
        return False
    return "public" in lowered or "external" in lowered or "function" in lowered


def _view(header: str) -> bool:
    lowered = header.lower()
    return "view" in lowered or "pure" in lowered


def _pick(functions: Iterable[dict], tokens: Iterable[str]) -> List[str]:
    names = []
    for item in functions:
        lowered = item["name"].lower()
        if any(token in lowered for token in tokens) and item["name"] not in names:
            names.append(item["name"])
    return names


def _body_has(item: dict, tokens: Iterable[str]) -> bool:
    hay = (item["body"] + item["header"]).lower()
    return any(token.lower() in hay for token in tokens)


def _static_specs(source: str, contract: str, source_path: str, corpus: str, address: str = "") -> List[dict]:
    functions = [item for item in _functions(source) if _public(item["header"]) and not _view(item["header"])]
    if not functions:
        return []
    specs: List[dict] = []
    lowered_source = source.lower()

    def add(family: str, function: str, variable: str, title: str) -> None:
        specs.append(
            {
                "corpus": corpus,
                "origin": "static_source",
                "contract": contract,
                "address": address,
                "source": source_path,
                "oracle_family": family,
                "review_family": "",
                "affected_function": function,
                "affected_variable": variable,
                "finding_title": title,
                "confidence": "source_pattern",
            }
        )

    transfers = [item for item in functions if item["name"].lower() in {"transfer", "transferfrom"}]
    gate_tokens = ("trading", "blacklist", "antibot", "isbot", "maxtx", "maxwallet", "cooldown", "pinkantibot", "launched")
    if transfers and any(token in lowered_source for token in gate_tokens):
        setter = next((item["name"] for item in functions if any(token in item["name"].lower() for token in ("trad", "bot", "black", "maxtx", "cooldown", "gate"))), "")
        add("transfer_gate_halt", transfers[0]["name"], setter or "trading", "contract exposes a transfer gate that can halt a later transfer")

    mint_burn = [item for item in functions if item["name"].lower() in {"mint", "burn", "burnfrom"} or item["name"].lower().startswith(("mint", "burn"))]
    if mint_burn and any(token in item["body"].lower() for item in mint_burn for token in ("totalsupply", "_mint", "_burn", "balance")):
        add("privileged_mint_or_burn", mint_burn[0]["name"], "totalSupply", "mint or burn updates balance or supply")

    fee_setters = [item for item in functions if any(token in item["name"].lower() for token in ("fee", "tax", "denominator", "divider"))]
    unbounded = []
    for item in fee_setters:
        body = item["body"]
        has_cap = bool(re.search(r"(<=|<)\s*[0-9]", body)) or "require" in body.lower() and any(token in body.lower() for token in ("cap", "max", "limit", "100", "1000"))
        if not has_cap:
            unbounded.append(item)
    if unbounded:
        add("critical_parameter_abuse", unbounded[0]["name"], unbounded[0]["name"], "fee or tax setter has no obvious numeric cap")
    elif re.search(r"/\s*[A-Za-z_][A-Za-z0-9_]*(fee|tax|denominator|divider)", source, re.I):
        add("critical_parameter_abuse", (fee_setters[0]["name"] if fee_setters else "transfer"), "denominator", "a fee path divides by a mutable denominator")

    if any(token in lowered_source for token in ("_rowned", "_towned", "rtotal", "ttotal", "rebase(")):
        target = next((item["name"] for item in functions if any(token in item["name"].lower() for token in ("burn", "transfer", "rebase", "reflect"))), "transfer")
        add("arithmetic_accounting_invariant", target, "totalSupply", "reflection or rebase accounting can diverge from balances")
    else:
        burns = [item for item in functions if "burn" in item["name"].lower()]
        if burns and "totalsupply" in lowered_source and all("totalsupply" not in item["body"].lower() for item in burns):
            add("arithmetic_accounting_invariant", burns[0]["name"], "totalSupply", "burn changes balance without updating totalSupply")

    transfer_from = [item for item in functions if item["name"].lower() == "transferfrom"]
    if transfer_from:
        body = transfer_from[0]["body"].lower()
        if "allowance" not in body and "_allowance" not in body and "spendallowance" not in body:
            add("allowance_not_consumed", "transferFrom", "allowance", "transferFrom does not update allowance")

    for item in functions:
        if re.search(r"address\s*\[\s*\]", item["header"]) and re.search(r"\bfor\s*\(", item["body"]):
            add("long_list_out_of_gas", item["name"], "address_list", "public function loops over an address-array argument")
            break

    ownership = [item for item in functions if "transferowner" in item["name"].lower()]
    role_setter = [
        item for item in functions
        if any(token in item["body"].lower() for token in ("msg.sender == operator", "msg.sender == deployer", "msg.sender == marketing", "msg.sender == _admin", "msg.sender==operator"))
    ]
    if ownership and role_setter and not any(token in ownership[0]["body"].lower() for token in ("operator", "deployer", "marketing", "_admin")):
        add("residual_privilege_after_ownership_transfer", ownership[0]["name"], "operator", "ownership handoff leaves a second role able to set state")

    initializers = [item for item in functions if item["name"].lower() in {"initialize", "init"}]
    if initializers and re.search(r"owner\s*=", initializers[0]["body"], re.I):
        header = initializers[0]["header"].lower()
        if "initializer" not in header and "onlyowner" not in header:
            add("initialization_takeover", initializers[0]["name"], "owner", "initializer writes owner without an initializer guard")

    receiver_names = []
    for item in functions:
        match = re.search(r"(wallet|receiver|treasury|marketingWallet|feeReceiver)\s*=", item["body"], re.I)
        if match and any(token in item["name"].lower() for token in ("set", "update")):
            receiver_names.append((item["name"], match.group(1)))
    if receiver_names and transfers:
        setter_name, variable = receiver_names[0]
        if variable.lower() in " ".join(item["body"].lower() for item in transfers):
            add("asset_flow_redirection", setter_name, variable, "a setter writes a receiver that transfer later reads")

    claims = [item for item in functions if item["name"].lower() in {"claim", "harvest", "getreward"}]
    if claims and any(token in claims[0]["body"].lower() for token in ("transfer", ".call", "send")):
        if not any(token in claims[0]["body"].lower() for token in ("claimed", "pending", "rewarddebt", "harvested", "user.reward")):
            add("repeat_claim_no_reset", claims[0]["name"], "claimed", "claim pays without an obvious claimed-state reset")

    for item in functions:
        if ".call" in item["body"] and "success" not in item["body"].lower() and re.search(r"=\s*", item["body"]):
            add("unchecked_external_call_effect", item["name"], "call", "external call success is ignored around a state write")
            break

    if any(token in lowered_source for token in ("blacklist", "whennotpaused", "isblacklisted")) and transfers:
        guarded = [item for item in transfers if any(token in item["body"].lower() for token in ("black", "pause", "lock"))]
        unguarded = [item for item in transfers if item not in guarded]
        if guarded and unguarded:
            add("lock_pause_blacklist_bypass", unguarded[0]["name"], "paused", "a sibling transfer path does not read the restriction")

    for item in functions:
        if any(token in item["name"].lower() for token in ("initialize", "init", "transferowner", "constructor")):
            continue
        header = item["header"].lower()
        if any(token in header for token in ("onlyowner", "onlyadmin", "onlyrole", "auth")):
            continue
        if re.search(r"(\bowner\b|_owner|\badmin\b)\s*=", item["body"], re.I):
            add("access_control_state_change", item["name"], "owner", "role storage is written without a privilege modifier")
            break

    seen = set()
    unique = []
    for spec in specs:
        if spec["oracle_family"] in seen:
            continue
        seen.add(spec["oracle_family"])
        unique.append(spec)
    rank = {
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
    unique.sort(key=lambda item: rank.get(item["oracle_family"], 99))
    return unique[:4]


def _review_spec(row: dict) -> dict:
    review_family = str(row.get("family") or "")
    mapped = REVIEW_FAMILY_MAP.get(review_family, "")
    note = ""
    if not mapped and review_family in UNMAPPED_REVIEW_FAMILIES:
        note = "retained for traceability; not one of the thirteen confirmation families"
    elif not mapped:
        note = "review family has no thirteen-family mapping"
    return {
        "corpus": "realworld_reviewed",
        "origin": "reviewed_finding",
        "contract": row.get("name") or "",
        "address": row.get("address") or "",
        "source": row.get("source") or "",
        "oracle_family": mapped,
        "review_family": review_family,
        "review_module": row.get("review_module") or "",
        "uid": row.get("uid") or "",
        "affected_function": row.get("function") or "",
        "affected_variable": row.get("variable") or "",
        "finding_title": row.get("title") or "",
        "l1_condition": row.get("l1") or "",
        "l2_condition": row.get("l2") or "",
        "l3_condition": row.get("l3") or "",
        "required_trace_evidence": row.get("evidence") or "",
        "normalized_type": row.get("normalized_type") or "",
        "confidence": "reviewed" if mapped else "unmapped",
        "note": note,
    }


def _iter_sol(root: Path) -> Iterable[Path]:
    if not root.exists():
        return []
    found = []
    for path in root.rglob("*.sol"):
        if any(part.lower() in SKIP_DIRS for part in path.parts):
            continue
        found.append(path)
    return found


def _contract_name_from_file(path: Path) -> str:
    stem = path.stem
    if "__" in stem:
        return stem.split("__", 1)[0]
    return stem


def _address_from_path(path: Path) -> str:
    for part in path.parts:
        if part.lower().startswith("0x") and len(part) == 42:
            return part
    return ""


def build_catalog() -> dict:
    specs: List[dict] = []
    review_rows = _load_review_rows()
    reviewed_addresses = set()
    for row in review_rows:
        spec = _review_spec(row)
        spec["id"] = "review:{}".format(spec.get("uid") or len(specs))
        spec.update(_state_fields(spec["oracle_family"]))
        specs.append(spec)
        if spec.get("address"):
            reviewed_addresses.add(str(spec["address"]).lower())

    for spec in labeled_specs():
        spec.update(_state_fields(spec["oracle_family"]))
        specs.append(spec)

    paper = paper_specs()
    attach_paper_sources(paper, review_rows)
    for spec in paper:
        key = (str(spec.get("address") or "").lower(), spec.get("oracle_family"))
        existing = next(
            (
                item for item in specs
                if str(item.get("address") or "").lower() == key[0]
                and item.get("oracle_family") == key[1]
                and key[0]
            ),
            None,
        )
        if existing is not None:
            existing["paper_confirmed"] = True
            existing["paper_status"] = spec.get("paper_status") or existing.get("paper_status") or ""
            existing["chain"] = spec.get("chain") or existing.get("chain") or ""
            if spec.get("source") and not existing.get("source"):
                existing["source"] = spec.get("source")
            if spec.get("affected_function") and not existing.get("affected_function"):
                existing["affected_function"] = spec.get("affected_function")
            continue
        spec.update(_state_fields(spec["oracle_family"]))
        specs.append(spec)
        if spec.get("address"):
            reviewed_addresses.add(str(spec["address"]).lower())

    if VULN100_DIR.exists():
        for path in sorted(VULN100_DIR.glob("*.sol")):
            text = path.read_text(encoding="utf-8", errors="ignore")
            for spec in _static_specs(text, _contract_name_from_file(path), str(path), "forge_candidates"):
                spec["id"] = "forge:{}:{}".format(path.name, spec["oracle_family"])
                spec["source_aliases"] = [str(path)]
                spec.update(_state_fields(spec["oracle_family"]))
                specs.append(spec)

    summary = {
        "family_counts": dict(Counter(spec.get("oracle_family") or "unmapped" for spec in specs)),
        "corpus_counts": dict(Counter(spec.get("corpus") or "" for spec in specs)),
        "spec_count": len(specs),
        "unique_reviewed_addresses": len(reviewed_addresses),
    }
    return {
        "version": 1,
        "description": "PathPilot confirmation-oracle catalog. Built from the labeled 100-contract oracles, later reviewed real contracts, and the deployment table. No fuzzing run was launched.",
        "families": list(FAMILY_ORDER),
        "summary": summary,
        "specs": specs,
    }


def _state_fields(family: str) -> dict:
    state = FAMILY_STATES.get(family) or {}
    return {
        "entry_checkpoint": state.get("entry", ""),
        "state2_order": list(state.get("s2") or []),
        "state3_order": list(state.get("s3") or state.get("s3_chains") or []),
        "identity": state.get("identity", ""),
        "checkpoints": family_checkpoints(family) if family else [],
    }


def write_catalog(path: Optional[Path] = None) -> Path:
    target = path or CATALOG_PATH
    payload = build_catalog()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    summary_path = target.with_suffix(".md")
    lines = ["# PathPilot logic-oracle catalog", ""]
    lines.append("- Specs: {}".format(payload["summary"]["spec_count"]))
    lines.append("- Reviewed addresses: {}".format(payload["summary"]["unique_reviewed_addresses"]))
    lines.append("")
    lines.append("## Families")
    for name, count in sorted(payload["summary"]["family_counts"].items(), key=lambda item: (-item[1], item[0])):
        lines.append("- {}: {}".format(name or "unmapped", count))
    lines.append("")
    lines.append("## Corpus")
    for name, count in sorted(payload["summary"]["corpus_counts"].items()):
        lines.append("- {}: {}".format(name, count))
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def main() -> None:
    path = write_catalog()
    payload = json.loads(path.read_text(encoding="utf-8"))
    print(path)
    print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
