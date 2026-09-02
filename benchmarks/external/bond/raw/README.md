# BOND raw 真实运行落盘区

待 **8/31 机器 job** 真实运行后，将下列产物落盘到本目录：

- `run-<fw>-<ts>/Bond_result/` — action_find（入口点）+ custom_analysis（约束）
- `run-<fw>-<ts>/fuzz_log/fuzz_sent_log.txt` — 发送记录 + TRIGGERED/crash/timeout 标记
- `run-<fw>-<ts>/report.json` — 解析后的 `external_finding`（带 `validation`）

机器前置（与 H8 一致）：

1. `config/dev.yaml`：`bond.enabled=true`，`authorized/local_lab/baseline_ready=true`，`simulate=false`，`target_ip=192.168.x.x`（私有）。
2. 启动隔离仿真 HTTP 服务；可选安装 Ghidra headless 并配置 `use_ghidra=true`。
3. 跑 `python scripts/run_external.py --tool bond --run-dir <dir>`。

> 本目录当前为空，属**诚实降级**：代码与契约就绪，但尚未保存一次授权仿真运行的真实产物。
