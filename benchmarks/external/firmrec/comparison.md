# FirmRec 复发专项实验（benchmarks/external/firmrec/comparison.md）

> F-FirmRec.md §6（F6）。核心实验：**用 A 固件 / A 组漏洞的签名 → 检测 B 固件中的变体**。
> 这是 FirmRec 真正的价值证明，也是答辩最高频被问的一招。

## 实验设计

- **签名来源（known）**：我们的 9-CVE 知识库（`vuln_info_source: our`）或官方样例
  （`official`），分别跑一遍做对照。
- **检测目标**：L2 DIR-859 + L3 两个真实固件（Tenda AC15 / Netgear R7000 类）。
- **度量**：
  - `recurrence_found`：检出的复发变体数（按 `matched_cve` 聚合）
  - `cross_vendor_hit`：跨厂商/跨型号命中数（最有说服力的指标）
  - `false_positive`：人工复核后判定为误报的数
  - `recall_vs_self`：用 A 固件签名能否找回 A 固件自身已知洞（自洽性校验）

## 结果表（真实跑完后填，当前 PENDING）

| 签名源 | 目标固件 | recurrence_found | cross_vendor_hit | false_positive | 耗时(s) | 备注 |
|---|---|---|---|---|---|---|
| our(9-CVE) | L2 DIR-859 | PENDING | PENDING | PENDING | PENDING | |
| our(9-CVE) | L3-a | PENDING | PENDING | PENDING | PENDING | 待固件 |
| our(9-CVE) | L3-b | PENDING | PENDING | PENDING | PENDING | 待固件 |
| official | L2 DIR-859 | PENDING | PENDING | PENDING | PENDING | 对照基线 |

## 结论写法（即使为 0 也有价值）

- 检出 >0：列出「CVE-X 的变体出现在固件 Y 的二进制 Z」，这是全场最炸的 3 分钟。
- 检出 =0：说明这批固件属不同代码谱系——**这本身是个结论**，正面写进报告。

## 运行方式

```bash
# 用我们的 9-CVE 签名对 L2 跑复发检测
python scripts/run_external.py --tool firmrec --run-dir runs/<firmrec-L2-our>

# 产物：recurrence_findings.json（含 matched_cve + 相似度）
# 把 matched_cve × 目标固件 的矩阵回填上表
```

> ⚠️ 该实验 **只用于 recurrence 专项**，绝不在 Blind Benchmark 开启 FirmRec（隔离四道闸）。
