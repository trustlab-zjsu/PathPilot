# PathPilot

PathPilot is a research fuzzer for smart-contract logic vulnerabilities. It combines evolutionary transaction-sequence generation with path hypotheses, runtime evidence, Global Execution Instrumentation (GEI), Path Assessment Instrumentation (PAI), Target Condition Instrumentation (TCI), optional LLM-assisted planning, and a confirmation oracle.

## Repository Layout

- `fuzzer/main.py`: command-line entry point and run orchestration.
- `fuzzer/engine/`: evolutionary search, transaction populations, EVM execution, and trace analysis.
- `fuzzer/guidance/`: path plans, checkpoint guidance, side-path guidance, and progress tracking.
- `fuzzer/agent/`: LLM provider, path planning, evidence feedback, and target-focus runtime.
- `fuzzer/metrics/`: paper-aligned VSPC and VPPR metric implementations.
- `fuzzer/oracles/`: the thirteen-family logic confirmation oracle and catalog utilities.
- `fuzzer/runtime/`: runtime evidence, timing, phase-cost, and result summaries.
- `fuzzer/dependencies/`: Solidity mocks and vendored dependencies used by supported compilation paths.
- `configs/`: example fuzzer settings and vulnerability taxonomy.
- `examples/`: a small path-plan example.
- `docs/`: implementation and figure references.
- `dataset_contracts/`: contract sources and manifests collected from public benchmark or on-chain sources. The dataset metadata records the source and checksum where available.

The public contract datasets are included for reproducibility. Generated results, local secrets, compiler caches, and machine-specific runtime files are kept outside this release.

## Requirements

- Python 3.10 or newer.
- A locally installed Solidity compiler supported by `py-solc-x`/Slither. Set `SOLC_DIR` or pass `--solc-dir` when the compiler is not in the default location.
- An RPC endpoint only when running against a deployed contract or remote chain state.
- LLM credentials only when enabling LLM-assisted planning.

## Install

From the repository root:

```powershell
python -m pip install -r requirements.txt
```

For optional LLM planning, copy `.env.llm.example` to `.env` and provide your own endpoint and API key. Do not commit `.env` or place credentials in source files.

## Run

Fuzz a Solidity source file:

```powershell
python -m fuzzer.main `
  --source path\to\Contract.sol `
  --contract ContractName `
  --solc-dir path\to\solc `
  --time-budget 60 `
  --out out\contract-run
```

`--time-budget` is the maximum wall-clock time for this one fuzzing run, in seconds. The example uses 60 seconds as a short smoke-test budget; choose a longer value for experiments (for example, `600` or `3600`). It is equivalent to `--timeout` and does not change the dataset.

For an ABI and deployed contract, provide the ABI, contract address, and the required chain/RPC settings instead. Run `python -m fuzzer.main --help` for the complete option list.

Path planning and runtime evidence can be enabled with the corresponding CLI options. The repository includes `examples/sample_path_plan.json` as a minimal path-plan input; adapt contract function names and hypotheses to the target contract. LLM planning is optional and requires the endpoint settings in `.env`.

## Metrics

`fuzzer.metrics.path_metrics` contains the article-aligned metric calculations:

- `runtime_vppr` reports the original runtime statistic over deduplicated observed checkpoints.
- `trace_vppr_for_target` and `trace_vppr_macro_average` use State 1 sequences and the target-level macro average.
- `vspc_for_sequence` measures weighted progress along the longest valid ordered checkpoint prefix; `vspc_for_run` takes the maximum across sequences.

`strict_vspc` is an online guidance score. For paper reporting, calculate metrics from exported reference checkpoints and sequence traces using `fuzzer.metrics.path_metrics`.

## Logic Oracle

The confirmation oracle defines thirteen logic-vulnerability families. Enable it with `--enable-logic-oracle`. A compatible oracle catalog can be supplied with `--logic-oracle-catalog`; catalog construction utilities are available through `python -m fuzzer.oracles.build_catalog` and require the relevant input specifications.

## Validation

Run the focused oracle and metric tests from the repository root:

```powershell
$env:PYTHONPATH = (Resolve-Path .).Path
python -m pytest -q fuzzer/oracles/test_logic_oracle.py fuzzer/metrics/test_path_metrics.py
python -m compileall -q fuzzer
python -m fuzzer.main --help
```
