# 给 WorkBuddy / 协作开发者的约定

1. **Schema 冻结前不写业务代码**：T-02 完成前，只写目录、Schema、配置和空 `__init__.py`。
2. **任务依赖**：被依赖任务未通过 DoD，不得开始后续任务。
3. **路径与密钥**：全部来自 `config/*.yaml` + `.env`，禁止硬编码。
4. **日志结构化**：使用 `structlog` 输出 JSONL，禁止裸 `print`。
5. **安全红线**：`config/safety.yaml` 中的命令黑名单、IP/路径白名单不可绕过。
6. **失败恢复**：每个工具必须输出 `status` 字段（ok / degraded / failed），主链路遇到 degraded 可继续，failed 必须恢复或降级。
7. **文档同步**：修改 Schema 必须同步更新 `schemas/examples/` 和受影响模块。
