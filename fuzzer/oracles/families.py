# -*- coding: utf-8 -*-
"""Thirteen confirmation-oracle families used by PathPilot.

Checkpoint names and order follow the appendix state table. Guidance
templates for the original nine families are left unchanged; this module is
the independent CheckOracle.
"""

from __future__ import annotations

from typing import Dict, List, Tuple


FAMILY_ORDER: Tuple[str, ...] = (
    "access_control_state_change",
    "arithmetic_accounting_invariant",
    "asset_flow_redirection",
    "critical_parameter_abuse",
    "initialization_takeover",
    "lock_pause_blacklist_bypass",
    "transfer_gate_halt",
    "repeat_claim_no_reset",
    "unchecked_external_call_effect",
    "privileged_mint_or_burn",
    "allowance_not_consumed",
    "long_list_out_of_gas",
    "residual_privilege_after_ownership_transfer",
)

# Review-family names from the offline real-contract evaluators.
# Halt-style findings confirm a later revert, so they are transfer-gate halt,
# not lock/pause/blacklist bypass. Supply and burn-unit mismatches stay in
# the accounting family. Zero-slippage, rescue-to-owner, router-factory,
# public balance pull, and owner-only privilege are not separate families.
REVIEW_FAMILY_MAP: Dict[str, str] = {
    "antibot_transfer_halt": "transfer_gate_halt",
    "blacklist_transfer_halt": "transfer_gate_halt",
    "bot_flag_transfer_halt": "transfer_gate_halt",
    "burn_rate_transfer_halt": "transfer_gate_halt",
    "cannot_transfer_full_balance": "transfer_gate_halt",
    "external_protection_revert": "transfer_gate_halt",
    "generic_blacklist_halt": "transfer_gate_halt",
    "generic_max_tx_halt": "transfer_gate_halt",
    "generic_pause_transfer_halt": "transfer_gate_halt",
    "generic_trading_halt": "transfer_gate_halt",
    "named_blacklist_halt": "transfer_gate_halt",
    "owner_maxtx_halt": "transfer_gate_halt",
    "owner_restriction_revert": "transfer_gate_halt",
    "owner_trading_halt": "transfer_gate_halt",
    "pause_then_create_halt": "transfer_gate_halt",
    "pause_then_transfer_halt": "transfer_gate_halt",
    "pink_antibot_halt": "transfer_gate_halt",
    "scaled_max_tx_halt": "transfer_gate_halt",
    "swapper_gate_halt": "transfer_gate_halt",
    "transfer_from_exact_balance_revert": "transfer_gate_halt",
    "burn_event_balance_mismatch": "arithmetic_accounting_invariant",
    "burn_skips_supply": "arithmetic_accounting_invariant",
    "burn_supply_and_balance": "arithmetic_accounting_invariant",
    "burn_supply_balance_mismatch": "arithmetic_accounting_invariant",
    "burn_unit_mismatch": "arithmetic_accounting_invariant",
    "escrow_accounting_mismatch": "arithmetic_accounting_invariant",
    "mint_skips_known_supply": "arithmetic_accounting_invariant",
    "mint_skips_supply": "arithmetic_accounting_invariant",
    "transfer_shrinks_supply": "arithmetic_accounting_invariant",
    "fee_args_over_cap": "critical_parameter_abuse",
    "fee_cap_bypass": "critical_parameter_abuse",
    "fee_denominator_zero": "critical_parameter_abuse",
    "generic_mint_increase": "privileged_mint_or_burn",
    "owner_burn_other_balance": "privileged_mint_or_burn",
    "owner_mint_supply_increase": "privileged_mint_or_burn",
    "allowance_not_spent": "allowance_not_consumed",
    "loop_out_of_gas": "long_list_out_of_gas",
    "deployer_privilege_survives": "residual_privilege_after_ownership_transfer",
    "operator_privilege_survives": "residual_privilege_after_ownership_transfer",
}

UNMAPPED_REVIEW_FAMILIES = {
    "owner_only_privilege",
    "owner_token_drain",
    "prize_share_to_platform",
    "public_balance_pull",
    "public_rescue_to_owner",
    "public_zero_slippage_swap",
    "router_factory_pair_mismatch",
    "zero_slippage_full_balance_swap",
}

# entry, context chain for state 2, confirmation chain for state 3.
# A chain is an ordered list of checkpoint ids that must match inside one sequence.
FAMILY_STATES: Dict[str, Dict[str, object]] = {
    "access_control_state_change": {
        "entry": "protected_function_reached",
        "s2": ["protected_function_reached", "unexpected_sender_observed", "guarded_region_or_tx_success"],
        "s3": ["protected_function_reached", "unexpected_sender_observed", "guarded_region_or_tx_success", "critical_state_written"],
    },
    "arithmetic_accounting_invariant": {
        "entry": "accounting_path_reached",
        "s2": ["accounting_path_reached", "precision_supply_or_burn_operation_observed", "balance_or_supply_change_observed"],
        "s3": ["accounting_path_reached", "precision_supply_or_burn_operation_observed", "balance_or_supply_change_observed", "supply_balance_or_unit_mismatch_observed"],
    },
    "asset_flow_redirection": {
        "entry": "dependent_business_path_executed",
        "s2": ["critical_setter_reached", "receiver_or_fee_state_written", "dependent_business_path_executed", "asset_flow_sink_touched", "transfer_or_balance_change_observed"],
        "s3": ["critical_setter_reached", "receiver_or_fee_state_written", "dependent_business_path_executed", "asset_flow_sink_touched", "transfer_or_balance_change_observed", "funds_flow_to_changed_or_unexpected_receiver"],
        "identity": "C2.new_value == V.to",
    },
    "critical_parameter_abuse": {
        "entry": "parameter_setter_or_dependent_path_reached",
        "s2": ["parameter_setter_or_dependent_path_reached", "setter_succeeded", "unbounded_or_zero_denominator_value_observed"],
        "s3": ["parameter_setter_or_dependent_path_reached", "setter_succeeded", "unbounded_or_zero_denominator_value_observed", "over_cap_write_or_abnormal_effect"],
    },
    "initialization_takeover": {
        "entry": "init_function_reached",
        "s2": ["init_function_reached", "unexpected_sender_observed", "init_tx_success", "owner_admin_role_state_written"],
        "s3": ["init_function_reached", "unexpected_sender_observed", "init_tx_success", "owner_admin_role_state_written", "privileged_effect_after_takeover"],
        "identity": "C3.new_value == V.sender",
    },
    "lock_pause_blacklist_bypass": {
        "entry": "restricted_operation_called",
        "s2": ["restricted_state_observed", "restriction_active", "restricted_operation_called"],
        "s3": ["restricted_state_observed", "restriction_active", "restricted_operation_called", "restricted_operation_success"],
    },
    "transfer_gate_halt": {
        "entry": "gate_setter_or_transfer_reached",
        "s2": ["gate_setter_succeeded", "restriction_state_written"],
        "s3": ["gate_setter_succeeded", "restriction_state_written", "later_gated_transfer_reverted"],
        "identity": "address gate only: V.sender or V.to == written_addr",
    },
    "repeat_claim_no_reset": {
        "entry": "claim_like_function_reached",
        "s2": ["setup_or_balance_preparation_observed", "claim_like_function_reached", "first_claim_success", "second_claim_attempted", "second_claim_success_or_no_expected_revert"],
        "s3": ["setup_or_balance_preparation_observed", "claim_like_function_reached", "first_claim_success", "second_claim_attempted", "second_claim_success_or_no_expected_revert", "abnormal_balance_or_state_no_reset_observed"],
        "identity": "E.sender == C3.sender",
    },
    "unchecked_external_call_effect": {
        "entry": "external_call_reached",
        "s2": ["external_call_reached", "external_call_failed", "parent_tx_did_not_revert", "state_or_asset_effect_after_failed_call"],
        "s3": ["external_call_reached", "external_call_failed", "parent_tx_did_not_revert", "state_or_asset_effect_after_failed_call", "inconsistent_state_observed"],
    },
    "privileged_mint_or_burn": {
        "entry": "mint_or_burn_reached",
        "s2": ["mint_or_burn_reached", "mint_or_burn_succeeded"],
        "s3": ["mint_or_burn_reached", "mint_or_burn_succeeded", "balance_or_supply_changed"],
    },
    "allowance_not_consumed": {
        "entry": "transfer_from_reached",
        "s2": ["transfer_from_reached", "positive_transfer_from_succeeded"],
        "s3": ["transfer_from_reached", "positive_transfer_from_succeeded", "allowance_unchanged_or_reused"],
        "identity": "reuse only, same from and spender",
    },
    "long_list_out_of_gas": {
        "entry": "bulk_list_function_reached",
        "s2": ["bulk_list_function_reached", "long_address_list_observed"],
        "s3": ["bulk_list_function_reached", "long_address_list_observed", "out_of_gas_revert"],
    },
    "residual_privilege_after_ownership_transfer": {
        "entry": "ownership_or_setter_reached",
        "s2": ["ownership_transfer_succeeded", "new_owner_setter_reverted"],
        "s3_chains": [
            ["ownership_transfer_succeeded", "new_owner_setter_reverted"],
            ["ownership_transfer_succeeded", "old_role_setter_succeeded"],
        ],
        "identity": "V.sender != C1.new_owner; C2.sender == C1.new_owner",
    },
}


def family_checkpoints(family: str) -> List[str]:
    state = FAMILY_STATES.get(family) or {}
    if state.get("s3_chains"):
        seen = []
        for chain in state["s3_chains"]:
            for name in chain:
                if name not in seen:
                    seen.append(name)
        entry = state.get("entry")
        if entry and entry not in seen:
            seen.insert(0, entry)
        return seen
    return list(state.get("s3") or [])
