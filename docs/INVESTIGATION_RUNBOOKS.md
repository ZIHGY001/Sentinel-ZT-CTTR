# v0.4.0 应急手册与证据复核

Sentinel-ZT-CTTR 将两份资料中的调查方向接入现有行为基线工作流：**行为偏离 → 调查清单 → 证据核验 → 有边界的响应 → 基线复盘**。保持 React + FastAPI + Pi Agent 架构；新增能力离线运行，不增加运行时依赖。

## 接入了什么

| 流程 | 检查数 | 加入调查的条件 |
| --- | ---: | --- |
| 调查范围、证据与恢复 | 4 | 每个调查 |
| Linux 主机排查 | 6 | 分析员确认系统为 Linux |
| Windows 主机排查 | 3 | 分析员确认系统为 Windows |
| Web 异常执行与文件落地 | 2 | B002/B006/B008/B009/B010/B014/B015/C002 |
| 横向访问与路径偏离 | 2 | B016/B101/B102/C101/C003 |
| 异常授权与凭据访问 | 2 | B005/B007/B013/B103/B104/C101 |
| 异常外联与进程核验 | 2 | B018/I001/C001 |

[查看合成演练报告](runbook-demo-report.html)（全部检查初始待核验；无真实处置）。

共 7 类流程、21 项检查。每项包含调查目标、证据要求、误报与解释边界、来源链接及基线复盘方向。部分检查附固定的只读命令参考；平台不会插入日志参数，也没有执行手册命令的接口。

Linux 覆盖账户/SSH、cron/at/systemd、shell 启动配置、udev/Python .pth、动态加载/PAM、软件包与内核可信度等人工核验方向。**这些是检查项目，不表示已新增对应的自动检测器、远程采集器或 rootkit 查杀功能。**目录中的 Windows 步骤也不代表支持直接解析 EVTX。

命中规则只决定优先调查的方向，不证明失陷。系统类型必须人工选择，不根据日志标签、进程名称或 Quake 指纹推断。类型未知时仅生成通用及规则关联流程；确认类型后再建立清单，创建后类型固定，避免静默丢失已有记录。

## 在工作台使用

1. 启动工作台，运行“行为基线 → 无 IOC 行为演练”，或分析真实授权范围内的日志。
2. 打开“应急手册”，选择当前事件及人工确认的系统类型，点击“建立调查清单”。无 IOC 演练选择 Linux 时生成 14 项检查。
3. 逐项核验，在五种状态中选择：待检查、发现异常、已核验未见异常、缺少证据、不适用。填写记录人和依据。
4. “发现异常”和“已核验未见异常”必须绑定当前事件的证据 ID，或登记外部证据的名称、SHA256 与带时区的采集时间。无法提供证据时用“缺少证据”。“不适用”和重新打开检查也必须填写理由。
5. 保存后保留历次版次；重新加载或重启服务后可继续。若其他页面先保存，本次写入返回冲突，先保留输入、重新加载，再核对并提交。
6. 导出调查记录、基线复盘建议，或从事件研判页导出包含复核记录的 HTML 报告。

清单进度和风险评分分别展示；“已复核”包含发现异常与有理由的不适用，并非“安全项”。剩余待检查和缺少证据显示为未解决；不会自动关闭事件。外部证据文件需另外保全，平台只登记人工提供的摘要，不读取文件、不验证其真实性或保管链。

每个工作区调查最多 32 份资产清单，清单合计最多 2 MiB；每份最多 200 次复核。单次最多关联 30 个事件、10 个外部证据摘要，备注最多 2,000 字符。达到限制时归档工作区；不自动删除历史。

## 设计期反馈与云脉响应

复盘文件 `type=baseline_review_tasks` 只包含待审核任务，例如核对 B101 正常路径、B103 精确身份组合、C101 所需字段或日志留存。它不是可导入的策略，`enabled=false`、`changes_applied=false`，不会把已观测行为学习为正常行为，也不会生成允许列表或告警例外。

本轮没有更改原有响应权限：行为证据可进入人工云脉交接；云脉用户到应用访问限制仍由授权人员在租户控制台复核。Linux 本机 nftables 仍受有效 IP IOC、近期行为、资产范围、签名审批及显式 `--live` 约束。手册核验记录不解除这些门槛。

## CLI 与 API

```bash
python -m sentinel_zt runbook-catalog
python -m sentinel_zt behavior-demo --out output/behavior-demo
# 从 analysis.json 的 incidents 中选择实际的 id，替换 CASE_ID
python -m sentinel_zt runbook-plan \
  --analysis output/behavior-demo/analysis.json \
  --incident CASE_ID --platform linux --out output/investigation-checklist.json
```

CLI 生成初始清单，不直接修改工作台数据库。持久化复核通过工作台或以下带 Bearer 鉴权的 API 操作：

| 方法 / 路径 | 用途 |
| --- | --- |
| `GET /api/runbooks` | 离线手册及来源目录 |
| `GET /api/cases/{case_id}/runbooks` | 读取该次分析的调查清单 |
| `POST /api/cases/{case_id}/runbooks` | 提供 `incident_id`、`platform` 建立清单；相同参数重复调用保留已有记录 |
| `POST /api/cases/{case_id}/runbooks/{incident_id}/checks/{check_id}` | 保存有版次保护的人工核验结果 |

`case_id` 是工作台保存的分析 UUID；`incident_id` 是该分析中一台资产的事件 ID，二者不同。复核请求为：

```json
{
  "expected_revision": 0,
  "status": "needs_data",
  "reviewer": "Lab analyst",
  "observation": "等待资产负责人核对原始认证日志。",
  "evidence_ids": [],
  "artifacts": []
}
```

每个外部证据条目必须且只能提供 `name`、`sha256`、`collected_at`；后者需为不晚于当前时刻的带时区 ISO 时间。客户端不能提交命令、替换清单定义或引用其他事件证据。

## 来源与版本

- [NOP Team / Linux-INCIDENT-RESPONSE-COOKBOOK](https://github.com/Just-Hack-For-Fun/Linux-INCIDENT-RESPONSE-COOKBOOK)：读取仓库介绍及其链接的[在线手册](https://book.noptrace.com/)，重点核对准备、注意事项和常规安全检查。仓库 HEAD `480a9c88364f6deef97de25d5ad88ae29f94a930`，仓库标示 GPL-3.0。在线页面独立变化，未声称被此提交固定。
- [Bypass007 / Emergency-Response-Notes](https://github.com/Bypass007/Emergency-Response-Notes)：核对 Linux/Windows 入侵排查、Linux 日志、SSH 与 Webshell 案例。引用章节固定到 `693478ca87b30ff8f01fcb7ee9cb0a4dd07e492b`；检查时仓库元数据没有列出许可证。

检查日期：2026-09-22。平台保存原创调查步骤、关联规则和来源元数据，不分发上述项目正文、PDF、样本或脚本，也不将其纳入本项目 MIT 许可。目录版本为 `2026.09.22.1`；每份清单保存目录摘要与步骤快照，后续更改目录不会重写已建调查。

手册中的操作需要结合当前发行版、工具版本和授权范围复核。导入时未采用删除账号、清除 history、删除定时任务、停用服务、运行可疑程序或在线下载查杀脚本等命令。失败登录不等于登录成功、HTTP 成功不等于利用成立、实时进程列表不等于历史执行证据。

## 验证与限制

本轮新增 20 项 Python/API 回归，合计 228 项通过，0 失败、0 跳过；验证无 IOC 关联、平台边界、证据绑定、外部摘要校验、旧版写入冲突、历史保留、重启持久化、HTML 转义、反馈不能作为策略加载及无 Shell 调用。Pi 4 项、前端导入 3 项测试及 React 构建通过。Chromium 已验证演练建单、证据约束与错误恢复、保存后重载、复盘导出、目录检索及 390px 布局；0 页面脚本错误，无横向溢出。

工作台仍使用共享令牌。记录人是自行填写，不能作为已认证个人身份；调查清单历史通过 API 追加，数据库管理员仍可修改文件，因此不是签名取证保管链。原始日志真实性、手工证据结论和摘要仍需分析员核验。人工备注与外部证据摘要不进入 Pi 自动上下文。

不宣称完整覆盖 Linux/Windows 攻击面，也不宣称已在真实云脉租户执行过处置。本轮没有验证命令在全部发行版上的可用性，没有执行真实封禁，也未推送 GitHub；依赖版本未改变，未重新查询依赖漏洞数据库。
