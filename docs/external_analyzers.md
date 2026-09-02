# 外部分析器集成与降级说明

## 1. 目标与边界

外部轨补齐跨函数污点追踪、路径可行性判定、约束导向验证和复发漏洞扫描。
它是可选增强，不是主轨运行的前置条件。默认配置下 `external.enabled=false`，
CI 与 Blind Benchmark 不下载镜像、不访问网络、不依赖商业软件。

## 2. 固定编排顺序

1. `EXTERNAL_ANALYSIS`：并行运行 SaTC 与 FirmRec；Blind Run 强制跳过 FirmRec。
2. `FUSION`：将 SaTC 与主轨候选按 binary/sink/class 汇聚；FirmRec 独立保存。
3. `SYMEX_PRUNE`：KLEE 回写可达 witness 或不可达 counterevidence。
4. `RANK` / `VERIFY_TOP_K`：仍使用原十维 30 分制与反证规则。
5. `CONSTRAINED_VALIDATION`：mini-BOND 仅对授权仿真环境执行。
6. `REPORT`：第 21 节展示交叉验证、限制与隔离声明。

## 3. 安装与启用

先在 `config/dev.yaml` 打开总开关，再只开启本机具备依赖的工具。不要在 CI 配置中
打开重型工具。

```yaml
external:
  enabled: true
  satc:
    enabled: true
  firmrec:
    enabled: false
  klee:
    enabled: true
  bond:
    enabled: false
```

探测不会执行分析，也不会因缺失返回非零：

```bash
python scripts/dev.py ext-smoke
```

运行完整链：

```bash
python scripts/run_pipeline.py --benchmark-fixtures --depth full --out-dir runs/ext_full
```

默认是 Blind Run。只有已获授权的复发扫描专项才可使用 `--no-blind`，并且必须在报告
中保留“依赖已知漏洞签名，不属于零先验发现”的声明。

## 4. 能力与诚实降级

| 工具 | 依赖 | 缺失时状态 | 不可声称的能力 |
|---|---|---|---|
| SaTC | Docker、Ghidra、angr | skipped | 未跑真实镜像时不能声称完成跨函数实测 |
| FirmRec | Docker、PostgreSQL、已知漏洞签名 | skipped/FORCED_DISABLE | 不能计入 Blind 指标 |
| KLEE | LLVM bitcode、KLEE/Z3 | skipped/timeout | harness infeasible 不等于真实固件安全 |
| mini-BOND | 可选 Ghidra、隔离仿真目标、安全门 | skipped/unsafe | 内置限界 HTTP 探针；模拟模式不生成 finding |

当前仓库提供完整 Adapter、Parser、fixture、融合与降级测试；真实工具复现数据必须在
对应 `benchmarks/external/<tool>/README.md` 中记录版本、镜像、commit、机器环境和耗时。

## 5. 安全红线

- 工作目录仅允许 `./tmp/external/<tool>/<run_id>/`；
- BOND 目标只允许仿真与私有网段，且四道安全门全部通过；
- 禁止真机、公网、反弹 shell、持久化、下载执行和破坏性命令；
- LLM 调用走项目运行时，禁止 curl/wget；
- 只有 `poc_sanitized=true` 的 marker/crash 证据可确认候选。

## 6. CI 与验收

CI 运行确定性单元测试、Schema 示例校验、8 种开关降级测试、lint、外部探测以及
`--depth full` 全关闭回归。主机相关解包集成测试使用 `python scripts/dev.py integration`
单独运行，避免 Windows WSL 服务异常拖死基础 CI。
