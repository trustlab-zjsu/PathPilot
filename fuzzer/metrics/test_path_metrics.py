from fuzzer.metrics.path_metrics import (
    runtime_vppr,
    trace_vppr_for_target,
    trace_vppr_macro_average,
    vspc_for_run,
    vspc_for_sequence,
)


def test_vspc_empty_sequence_is_zero():
    assert vspc_for_sequence([], ["a", "b"]) == 0.0
    assert vspc_for_run([], ["a", "b"]) == 0.0


def test_vspc_uses_longest_ordered_prefix_and_checkpoint_weights():
    # b was observed first, so it cannot count before the required a checkpoint.
    assert vspc_for_sequence(["b", "a"], ["a", "b", "c"], [1, 3, 2]) == 1 / 6
    assert vspc_for_sequence(["a", "b"], ["a", "b", "c"], [1, 3, 2]) == 4 / 6


def test_vspc_run_takes_maximum_over_sequences():
    sequences = [["a"], ["a", "b", "c"]]
    assert vspc_for_run(sequences, ["a", "b", "c"]) == 1.0


def test_trace_vppr_uses_only_state_one_sequences():
    sequences = [
        {"state": "State 1", "checkpoints": ["a"]},
        {"state": "State 2", "checkpoints": ["a", "b"]},
    ]
    assert trace_vppr_for_target(sequences, ["a", "b"]) == 0.5


def test_trace_vppr_macro_average_zero_fills_targets_without_state_one():
    targets = [
        {"reference_checkpoints": ["a", "b"], "sequences": [{"state": 1, "checkpoints": ["a"]}]},
        {"reference_checkpoints": ["x"], "sequences": [{"state": 2, "checkpoints": ["x"]}]},
    ]
    assert trace_vppr_macro_average(targets) == 0.25


def test_runtime_vppr_deduplicates_observed_checkpoints():
    assert runtime_vppr(["a", "b"], ["a", "a", "z"]) == 0.5
    assert runtime_vppr(["a"], []) == 0.0
