# FirmHound CLI 测试方案

> 面向 XH-202609 比赛提交前自测。目标是证明 CLI 可运行、可解释、可降级，并明确哪些能力需要真实环境或主办方网关支持。

## 1. 本机快速自检

```powershell
python -m fsa.cli doctor --json-output
python -m fsa.cli doctor --include-external-probes --json-output
```

通过标准：

- `paths.status=ok`
- `schemas.status=ok`
- `runtime.default=offline` 时允许本地离线测试；接主办方安全网关前再检查 `model_api_key_present=true`
- 外部工具缺失只能显示 `degraded`，不能让命令异常退出

## 2. 任务理解测试

```powershell
python -m fsa.cli plan `
  --task "分析厂商为Tenda、型号AC15的固件，授权测试，完整分析。" `
  --firmware-path firmware_samples\L3-b-netgear-r7000.zip `
  --authorization-holder team1 `
  --json-output
```

通过标准：

- 输出 `status=ok`
- 能提取或保留 `vendor/model/depth`
- `depth=full` 时阶段包含 `EXTERNAL_ANALYSIS/FUSION/SYMEX_PRUNE/CONSTRAINED_VALIDATION`
- 缺授权或缺固件时输出 `requires_human_gate=true`，而不是伪造继续执行

## 3. 正式 CLI 冒烟测试

```powershell
python scripts/dev.py smoke
```

通过标准：

- 实际调用 `fsa analyze`
- 最终运行目录在 `runs/dev-smoke-*`
- `state/run_state.json` 中 `status=done`
- 生成 `report.md`、`final_verdict.json`、`artifacts/report_compliance.json`

## 4. 真实固件测试

已解包 rootfs：

```powershell
python -m fsa.cli analyze <ROOTFS_DIR> `
  --input-type rootfs `
  --depth standard `
  --authorization-holder <授权人或团队名> `
  --vendor <厂商> `
  --model <型号> `
  --json-output
```

固件镜像：

```powershell
python -m fsa.cli analyze <FIRMWARE_BIN_OR_CHK> `
  --input-type firmware `
  --depth standard `
  --authorization-holder <授权人或团队名> `
  --vendor <厂商> `
  --model <型号> `
  --json-output
```

通过标准：

- 主链状态 `done`
- `artifacts/rootfs.json` 记录输入类型和 rootfs 来源
- `artifacts/attack_surface.json`、`binary_summaries.json`、`candidates.json`、`verdict.json` 均存在
- 报告第 21 节包含外部工具状态，缺工具时只写限制，不写假命中

## 5. Full Depth 降级测试

```powershell
python -m fsa.cli analyze <ROOTFS_DIR> `
  --input-type rootfs `
  --depth full `
  --authorization-holder <授权人或团队名> `
  --json-output
```

通过标准：

- 四个外部工具默认关闭时仍 `status=done`
- `external_findings` 目录存在或阶段产物记录 `skipped/degraded`
- FirmRec 不进入 `unified_candidates.json`
- BOND 没有 `poc_sanitized=true` 时不能把候选确认成真漏洞

## 6. 真实外部工具验证

需要逐个打开 `config/dev.yaml` 的 `external.enabled` 和对应工具开关。建议一次只开一个工具：

- SaTC：需要 Docker 镜像、Ghidra/angr 环境、至少一个 Web 固件 rootfs
- KLEE：需要 KLEE/LLVM 或 Docker，最好提供源码或可生成 harness 的候选
- BOND：只允许仿真目标，必须设置私有网段 IP、授权、baseline、无害 marker
- FirmRec：只用于复发漏洞专项，Blind Run 必须关闭

通过标准：

- 工具可用时输出 `status=ok`
- 工具不可用时输出 `degraded/skipped` 和明确 `limitation`
- 所有 PoC 或请求证据必须脱敏，不得出现真实攻击载荷

## 7. 你需要提供给我什么

- 至少 1 个你们有授权分析的真实固件文件，或已经解包的 rootfs 目录
- 厂商、型号、版本，如果不知道也可以留空
- 授权说明：自有设备、实验室授权、公开固件离线分析等
- 是否允许本地隔离仿真；如果允许，提供仿真目标的私有 IP、端口、无害 marker
- 若要测在线模型：主办方 AI 安全网关地址、模型 API key 环境变量名、模型名、调用规范
- 若要测 FirmRec：已知漏洞签名来源，并确认这是复发检测专项，不计入 Blind 指标

## 8. 比赛评分对照

- 任务理解与执行设计：用 `fsa plan` 展示自然语言/压缩包到执行计划的解析结果
- 系统架构与工程实现：用 `doctor`、`smoke`、`analyze` 展示可部署、可运行、可恢复
- 决策逻辑与可解释性：检查 `decisions/`、`evidence/`、`report.md`
- 工具协同与扩展能力：用 `--depth full` 展示四工具降级与融合链路
- 创新与附加价值：需要真实固件 run 的 External-Only Hits、FP Prune Rate、Confirm Uplift 数据支撑
