# FirmRec `vuln_info` 映射表（我们 9-CVE 知识库 → FirmRec 签名格式）

> F-FirmRec.md §5.2（X2）。我们的 9 个 CVE 来自 `benchmarks/CVEs/<CVE>/`，用于方法论沉淀与
> 回归验证，**不是比赛现场的答案库**。下面是把它们转成 FirmRec `vuln_info` 的映射，并**明确
> 标注哪些是推定的**——推定不等于事实（学术诚信）。

生成脚本：`tools/external/firmrec/vuln_info.py::collect_our_vuln_info`，落盘
`tools/external/firmrec/vuln_info_dataset.json`（已生成，9 条）。

## 字段来源与可信度

| 字段 | 来源 | 可信度 | 说明 |
|---|---|---|---|
| `cve_id` | candidate.metadata.cve_id | 事实 | |
| `device` | candidate.metadata.device | 事实 | 厂商/型号来自 fixture |
| `vuln_class` | candidate.vuln_class_hypothesis | 事实 | 主轨假设的漏洞类 |
| `sink.function` | candidate.sink.function | 事实 | 下沉函数（system/strcpy/memcpy） |
| `source.name/type` | candidate.source | 事实 | 攻击入口参数 |
| `entry.function` | candidate.entry.function | 事实 | 处理入口函数 |
| `entry.addr` | candidate.entry.addr | **推定** | fixture 全部为 `0x00405000`，属占位，非真实地址 |
| `binary_id` | candidate.binary_id | **推定** | `bin-CVE-xxxx` 是抽象 id，**不是真实 rootfs 路径**，须现场映射 |
| `call_chain` | candidate.call_chain | 事实 | 函数级调用链 |
| `verdict` | verdict.json.verdicts[0].action | 事实 | ACCEPT / NEED_DYNAMIC |
| `references` | candidate.metadata.references | 事实 | 公开披露链接 |

每条记录都标 `presumed=true`，提醒下游：抽象 fixture 推定的字段不可当真实证据。

## 9-CVE 映射一览

| CVE | 设备 | 漏洞类 | 入口函数 | 下沉函数 | binary_id（抽象） | 判定 |
|---|---|---|---|---|---|---|
| CVE-2017-17215 | Huawei HG532e | command_injection | Upgrade | system | bin-CVE-2017-17215 | ACCEPT |
| CVE-2018-5767 | D-Link DIR-8xx | command_injection | SetRouterSettings | system | bin-CVE-2018-5767 | ACCEPT |
| CVE-2019-16920 | D-Link DIR-8xx | command_injection | login_handler | system | bin-CVE-2019-16920 | ACCEPT |
| CVE-2019-17621 | D-Link DIR-859 | command_injection | soap_main | system | bin-CVE-2019-17621 | ACCEPT |
| CVE-2020-10987 | D-Link DIR-8xx | command_injection | formReboot | system | bin-CVE-2020-10987 | ACCEPT |
| CVE-2020-9373 | TP-Link Archer | command_injection | xxx_handler | system | bin-CVE-2020-9373 | ACCEPT |
| CVE-2021-31802 | NETGEAR R7000 | overflow | http_request_handler | strcpy | bin-CVE-2021-31802 | ACCEPT |
| CVE-2023-27021 | Tenda | command_injection | formSetOnlineDevName | system | bin-CVE-2023-27021 | ACCEPT |
| CVE-2023-32154 | MikroTik RouterOS | other | ipv6_neighbor_discovery | memcpy | bin-CVE-2023-32154 | NEED_DYNAMIC |

> 8 个 command_injection/overflow 的 `sink.function` 是 `system`/`strcpy`/`memcpy`（通用
> 下沉函数），真实固件里函数名可能不同——FirmRec 用「利用过程语义签名」而非函数名匹配，
> 所以 bin_id 抽象化不影响签名匹配，但**映射表必须如实标注 bin_id 是抽象的**。

## 与官方 `vuln_info` 的差异

官方 FirmRec 样例的 `vuln_info` schema 以其仓库 `inout/` 为准（先跑通官方样例再照抄格式）。
本仓库 `vuln_info_dataset.json` 是我们的最佳努力映射，字段名已对齐 FirmRec 常见结构
（cve_id / device / vuln_class / entry / source / sink / call_chain / verdict / references）。
若官方样例 schema 有出入，以官方为准，本文件仅作「用我们自己的漏洞知识库做复发检测」的对照。
