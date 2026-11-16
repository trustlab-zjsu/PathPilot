# Real-world completed-run dataset

该目录收录 `realworld contract` 中有完整 PathPilot/CrossFuzz 运行摘要的真实合约。
样本按链上地址去重；源码保持逐字节不变，并在清单中记录 SHA-256。

## 规模

- 总样本：103
- 人工确认 L3 复现正样本：53
- 已运行但未进入人工正样本集：50

> `ran_not_curated_positive` 只表示不在 `runed/index.csv` 中，不能解释为安全、无漏洞或严格负样本。

## 复现类别

- 两者都复现合约：3
- 原漏洞复现合约：18
- 新漏洞复现合约：32

## 批次分布

- initial：7
- 2：16
- 3：4
- 4：7
- 5：11
- 6：5
- 7：37
- 8：3
- 9：8
- 10：5

## 文件

- `contracts/`：实际运行使用的 Solidity 源码。
- `manifest.csv`：便于统计分析的平面清单（UTF-8 with BOM）。
- `manifest.json`：等价的结构化清单及数据集级元数据。

`run_summary_path` 是相对于 `E:/experiment` 的证据路径。源运行输出没有复制进仓库，避免把大型实验产物重复提交。

## 重建

从 `E:/experiment/PathPilot` 运行：

```powershell
py -3 scripts/build_realworld_ran_dataset.py --replace
```
