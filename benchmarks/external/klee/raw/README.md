# KLEE raw 产物落盘

8/31 真实符号执行产出的 `klee-out-N/` 目录（每个候选一份，N = 候选序号）落在此处，
用于复盘与抽检。目录结构（与 parser 期望一致）：

```
raw/<run_id>/klee-out-N/
  info          # KLEE 版本 + 调用参数
  run.stats      # instructions / states / completed paths / time（性能基线 F9）
  warnings.txt   # timeout / fork-limit 标记
  *.err          # ptr.err / free.err / div.err / overflow.err / assert.err（证据）
                  # model.err / exec.err（limitation，非漏洞）
  test*.ktest    # 到达 sink 的具体输入（witness，给 BOND）
```

注意：`model.err` / `exec.err` 不是漏洞证据；parser 已显式将其路由到 `limitation`。
