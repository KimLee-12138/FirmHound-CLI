# Skill 02：攻击面枚举

## 目标

从已解包的 rootfs 出发，输出完整的 `attack_surface.json`，覆盖 Web/CGI、UPnP/SOAP、socket daemon 三类入口。

## 核心原则

**端点不止在 webroot，必须“文件系统枚举 + 二进制内嵌端点反推 + 启动脚本 + 监听线索”四路并进。**

## 输入

- `rootfs_dir`：已解包的 rootfs 目录
- `run_id` / `run_root`：运行标识与输出目录

## 输出

- `attack_surface.json`（符合 `attack_surface.schema.json`）
- 每个 surface 条目包含：surface_id、category、protocol、binary、route、handler、input_sources、auth_hint、startup_evidence、reachability_hint、confidence、evidence_ids

## 执行流程

1. **文件系统清单** (`tools/filesystem/inventory.py`)
   - 统计 ELF、脚本、配置文件、启动脚本
   - 定位 webroot 候选（`www`/`htdocs`/`web`/`html`）

2. **启动脚本解析** (`tools/filesystem/startup_parse.py`)
   - 扫描 `etc/init.d/`、`rcS`、`rc.local`、`inittab`
   - 提取服务启动命令与参数，生成 `source_file:line` 证据

3. **Webroot 枚举** (`tools/web/webroot_enum.py`)
   - 枚举 webroot 下 `.cgi/.asp/.aspx/.php/.lua/.json/.xml/.html` 文件
   - 对 `goform/`、`cgi-bin/` 目录无后缀文件也视为端点
   - 按功能分类：auth / config / command / upgrade / status / debug

4. **二进制端点反推** (`tools/web/handler_extract.py`)
   - **GoAhead 系**：提取 `formXxx`/`fromXxx` 函数名 + `websFormDefine` 注册痕迹 → `/goform/<handler>`
   - **通用 CGI**：`.cgi` 字符串、URL 路由字符串（`^/` 且多层路径）
   - **环境变量**：`HTTP_*` 字符串暗示 Web handler
   - 输出端点 → 二进制 → handler 三元组

5. **UPnP 解析** (`tools/web/upnp_parse.py`)
   - 查找含 `<actionList>` 的 XML
   - 提取 Action 名、`direction=in` 输入参数
   - 高影响操作标记：Upgrade、Reboot、FactoryReset、SetPersistent

6. **认证矩阵** (`tools/web/auth_matrix.py`)
   - L1 路由层：`noauth`/`skip_auth`/`whitelist`/`public` 等豁免标记
   - L2 handler 层：检查二进制中是否调用 `sess_validate`/`check_auth`/`is_login`/`verify_token`/`auth_check`/`require_auth`
   - L3 脚本层：检查 `AUTHORIZED_GROUP`/`http_session`/`session_id`/`check_user`/`login_check`
   - 输出 `auth_hint` 与置信度

7. **组合输出** (`tools/web/build_attack_surface.py`)
   - 合并以上所有来源，去重（按 route+handler）
   - 校验 `attack_surface.schema.json`
   - 写入 `runs/<run_id>/attack_surface.json`

## 失败降级路径

| 场景 | 行为 |
|---|---|
| webroot 不存在 | 仅依赖二进制反推 + 启动脚本 |
| 二进制不是 ELF | 跳过 handler_extract |
| UPnP XML 解析失败 | 记录 `error`，继续其他来源 |
| 无启动脚本 | daemon 类 surface 不生成 |

## 验收标准

- AC15-like 固件：必须枚举出 `/goform/formexeCommand`
- HG532e-like 固件：必须枚举出 UPnP `Upgrade` Action 与 `NewDownloadURL`/`NewStatusURL`
- 内部 IPC/本地服务不误标为外部攻击面（用启动证据与 reachability_hint 区分）
