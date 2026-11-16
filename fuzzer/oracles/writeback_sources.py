# -*- coding: utf-8 -*-
"""Load the labeled 100-contract oracles and the deployment-table contracts."""

from __future__ import annotations

import json
import re
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from fuzzer.oracles.families import FAMILY_ORDER, REVIEW_FAMILY_MAP


CLEAN100_SPECS = Path(os.environ.get("PATHPILOT_CLEAN100_SPECS", ""))
PAPER_TABLE = Path(os.environ.get("PATHPILOT_PAPER_TABLE", ""))
PAPER_TABLE_FALLBACKS = (
    Path(os.environ.get("PATHPILOT_MAIN_TEX", "")),
)
REALWORLD_DIR = Path(os.environ.get("PATHPILOT_REALWORLD_DIR", ""))

PAPER_CODE_MAP = {
    "AAI": "arithmetic_accounting_invariant",
    "ANC": "allowance_not_consumed",
    "CPA": "critical_parameter_abuse",
    "PB": "critical_parameter_abuse",
    "LLOG": "long_list_out_of_gas",
    "PMB": "privileged_mint_or_burn",
    "RPO": "residual_privilege_after_ownership_transfer",
    "TG": "transfer_gate_halt",
}

SKIP_DIRS = {"node_modules", "vendor", "openzeppelin", ".git", "__pycache__"}


def latex_contract_name(cell: str) -> str:
    chunks = re.findall(r"\{([^{}]*)\}", cell)
    text = " ".join(chunks) if chunks else cell
    text = text.replace("\\\\", "")
    text = re.sub(r"\\[A-Za-z]+", "", text)
    return re.sub(r"[^A-Za-z0-9]+", "", text)


def latex_address(cell: str) -> str:
    cleaned = cell.replace("\\allowbreak{}", "").replace("\\allowbreak", "").replace("\\", "")
    found = re.search(r"0x[0-9a-fA-F]{40}", cleaned)
    return found.group(0) if found else ""


def parse_paper_rows(path: Optional[Path] = None) -> List[dict]:
    if path is not None:
        table = Path(path)
    else:
        table = next(
            (candidate for candidate in (PAPER_TABLE,) + PAPER_TABLE_FALLBACKS if candidate.exists()),
            PAPER_TABLE,
        )
    if not table.is_file():
        return []
    grouped: Dict[tuple, dict] = {}
    for line in table.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = [part.strip() for part in line.split("&")]
        if len(parts) < 5:
            continue
        address = latex_address(parts[1])
        if len(address) != 42:
            continue
        name = latex_contract_name(parts[0])
        code_index = None
        for index, part in enumerate(parts[2:], start=2):
            codes = [item.strip() for item in part.split(",")]
            if any(code in PAPER_CODE_MAP for code in codes):
                code_index = index
                break
        if code_index is None:
            continue
        if code_index >= 4:
            chain = parts[2].strip()
            status = parts[3].strip()
        else:
            chain = ""
            status = parts[3].strip() if len(parts) > 3 else ""
        asset = parts[code_index + 1].strip() if len(parts) > code_index + 1 else ""
        asset = asset.replace("\\", "").replace("$", "")
        for code in [item.strip() for item in parts[code_index].split(",")]:
            family = PAPER_CODE_MAP.get(code)
            if not family:
                continue
            key = (address.lower(), family)
            row = grouped.get(key)
            if row is None:
                grouped[key] = {
                    "contract": name,
                    "address": address,
                    "chain": chain,
                    "status": status,
                    "oracle_family": family,
                    "review_family": code,
                    "assets": [asset] if asset and asset != "--" else [],
                }
                continue
            if asset and asset != "--" and asset not in row["assets"]:
                row["assets"].append(asset)
    return list(grouped.values())


def paper_specs(path: Optional[Path] = None) -> List[dict]:
    specs = []
    for row in parse_paper_rows(path):
        specs.append(
            {
                "id": "paper:{}:{}".format(row["address"].lower(), row["oracle_family"]),
                "corpus": "paper_confirmed",
                "origin": "paper_table",
                "contract": row["contract"],
                "address": row["address"],
                "chain": row["chain"],
                "paper_status": row["status"],
                "quote_assets": row["assets"],
                "source": "",
                "source_aliases": [],
                "oracle_family": row["oracle_family"],
                "review_family": row["review_family"],
                "affected_function": "",
                "affected_variable": "",
                "finding_title": "{} confirmed in the deployment table".format(row["oracle_family"].replace("_", " ")),
                "confidence": "paper_table",
                "paper_confirmed": True,
            }
        )
    return specs


def labeled_specs(path: Optional[Path] = None) -> List[dict]:
    target = path or CLEAN100_SPECS
    if not target.is_file():
        return []
    payload = json.loads(target.read_text(encoding="utf-8"))
    specs = []
    for row in payload:
        family = str(row.get("oracle_family") or "")
        if family not in FAMILY_ORDER:
            continue
        aliases = []
        for key in ("archived_source_path", "contract_path"):
            value = str(row.get(key) or "")
            if value and value not in aliases:
                aliases.append(value)
        bench = str(row.get("bench_contract_id") or "")
        specs.append(
            {
                "id": "vuln100:{}".format(bench or len(specs)),
                "corpus": "vuln100",
                "origin": "labeled_benchmark",
                "contract": row.get("contract_name") or "",
                "address": "",
                "source": aliases[0] if aliases else "",
                "source_aliases": aliases,
                "bench_contract_id": bench,
                "oracle_family": family,
                "review_family": "",
                "affected_function": row.get("affected_function") or "",
                "affected_variable": row.get("affected_variable") or "",
                "finding_title": row.get("finding_title") or "",
                "l1_condition": row.get("l1_condition_text") or "",
                "l2_condition": row.get("l2_condition_text") or "",
                "l3_condition": row.get("l3_condition_text") or "",
                "required_trace_evidence": row.get("required_trace_evidence") or "",
                "normalized_type": row.get("normalized_type") or "",
                "confidence": "labeled",
                "audit_reason": row.get("audit_reason") or "",
            }
        )
    return specs


def address_dirs(root: Optional[Path] = None) -> Dict[str, str]:
    base = root or REALWORLD_DIR
    found: Dict[str, str] = {}
    if not base.exists():
        return found
    for path in base.rglob("*"):
        if not path.is_dir():
            continue
        name = path.name
        if name.lower().startswith("0x") and len(name) == 42:
            found.setdefault(name.lower(), str(path))
    return found


def sol_in(directory: str, contract: str = "") -> str:
    root = Path(directory)
    if not root.exists():
        return ""
    sols = []
    for path in root.rglob("*.sol"):
        if any(part.lower() in SKIP_DIRS for part in path.parts):
            continue
        sols.append(path)
    if not sols:
        return ""
    needle = (contract or "").lower()
    ranked = sorted(sols, key=lambda item: (needle not in item.stem.lower(), len(item.parts), len(str(item))))
    return str(ranked[0])


def guess_binding(source: str, family: str) -> tuple:
    from fuzzer.oracles.build_catalog import _functions, _public, _view

    functions = [item for item in _functions(source) if _public(item["header"]) and not _view(item["header"])]

    def first(pred, default=""):
        for item in functions:
            if pred(item):
                return item["name"]
        return default

    if family == "transfer_gate_halt":
        return (
            first(lambda item: item["name"].lower() in {"transfer", "transferfrom"}, "transfer"),
            first(lambda item: any(token in item["name"].lower() for token in ("trad", "black", "bot", "pause", "maxtx", "cooldown"))),
        )
    if family == "critical_parameter_abuse":
        return first(lambda item: any(token in item["name"].lower() for token in ("fee", "tax", "rate", "denominator"))), ""
    if family == "privileged_mint_or_burn":
        return first(lambda item: "mint" in item["name"].lower() or "burn" in item["name"].lower()), "totalSupply"
    if family == "arithmetic_accounting_invariant":
        return first(lambda item: any(token in item["name"].lower() for token in ("burn", "transfer", "rebase", "reflect")), "transfer"), "totalSupply"
    if family == "allowance_not_consumed":
        return "transferFrom", "allowance"
    if family == "long_list_out_of_gas":
        return first(lambda item: "address[" in item["header"].replace(" ", "")), ""
    if family == "residual_privilege_after_ownership_transfer":
        return first(lambda item: "transferowner" in item["name"].lower(), "transferOwnership"), "owner"
    return "", ""


def attach_paper_sources(specs: Iterable[dict], review_rows: Iterable[dict], directories: Optional[Dict[str, str]] = None) -> None:
    by_address: Dict[str, List[dict]] = {}
    for row in review_rows:
        address = str(row.get("address") or "").lower()
        if address:
            by_address.setdefault(address, []).append(row)
    directories = directories if directories is not None else address_dirs()
    for spec in specs:
        if spec.get("origin") != "paper_table":
            continue
        address = str(spec.get("address") or "").lower()
        family = spec.get("oracle_family") or ""
        matched = None
        for row in by_address.get(address, []):
            if REVIEW_FAMILY_MAP.get(str(row.get("family") or "")) == family:
                matched = row
                break
        source = ""
        if matched and matched.get("source"):
            source = str(matched.get("source"))
            spec["affected_function"] = matched.get("function") or spec.get("affected_function") or ""
            spec["affected_variable"] = matched.get("variable") or spec.get("affected_variable") or ""
            spec["l1_condition"] = matched.get("l1") or ""
            spec["l2_condition"] = matched.get("l2") or ""
            spec["l3_condition"] = matched.get("l3") or ""
            spec["required_trace_evidence"] = matched.get("evidence") or ""
            spec["finding_title"] = matched.get("title") or spec.get("finding_title") or ""
            spec["review_family"] = matched.get("family") or spec.get("review_family") or ""
        if not source:
            directory = directories.get(address, "")
            if directory:
                source = sol_in(directory, spec.get("contract") or "")
        if source:
            spec["source"] = source
            aliases = list(spec.get("source_aliases") or [])
            if source not in aliases:
                aliases.append(source)
            directory = directories.get(address, "")
            if directory and directory not in aliases:
                aliases.append(directory)
            spec["source_aliases"] = aliases
        if source and not spec.get("affected_function") and Path(source).is_file():
            text = Path(source).read_text(encoding="utf-8", errors="ignore")
            if len(text) > 1500000:
                text = text[:1500000]
            function_name, variable = guess_binding(text, family)
            if function_name:
                spec["affected_function"] = function_name
            if variable and not spec.get("affected_variable"):
                spec["affected_variable"] = variable
