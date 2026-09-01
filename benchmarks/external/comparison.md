# 外部分析器三组对照实验总表

## 状态

`status: degraded`

本表区分“CI 已验证的集成能力”和“必须在真实工具环境补测的效果指标”。仓库当前可
证明统一契约、融合、先验隔离与缺失降级；未在本机运行的 SaTC/KLEE/BOND/FirmRec
不得填入虚构性能数据。

## CI 可复现结果

| 项目 | 结果 | 证据 |
|---|---:|---|
| 外部 finding Schema + 示例 | 通过 | `tests/unit/test_schemas.py` |
| 四工具 fixture parser | 通过 | `test_external_{satc,firmrec,klee,bond}.py` |
| 8 种开关不 abort | 8/8 | `test_external_integration.py` |
| FirmRec Blind 隔离 | 通过 | `test_recurrence_isolation.py` |
| KLEE 保守回写 | 通过 | `test_external_evidence_application.py` |
| BOND 脱敏确认闸门 | 通过 | `test_external_evidence_application.py`、`test_sanitize.py` |
| full 深度全关闭回归 | 通过 | `test_pipeline.py::test_full_depth_degrades_and_writes_external_artifacts` |

## 真实工具待测表

| 固件 / CVE | A: Top-1/3/5 | A: 误报 | B: Top-1/3/5 | B: 误报 | C: 确认数 | C: 耗时 | External-Only |
|---|---|---|---|---|---|---|---|
| CVE-2017-17215 | 待实测 | 待实测 | 待实测 | 待实测 | 待实测 | 待实测 | 待实测 |
| CVE-2020-10987 | 待实测 | 待实测 | 待实测 | 待实测 | 待实测 | 待实测 | 待实测 |
| CVE-2019-16920 | 待实测 | 待实测 | 待实测 | 待实测 | 待实测 | 待实测 | 待实测 |

完成真实复现后必须同时记录镜像/commit、CPU/内存、超时预算、原始脱敏产物与失败原因。
