# 行为基线：把响应条件前置到设计期

v0.3.0 将日常已审核的资产角色、远程管理路径和权限工作流固化为可版本化策略。检测读取原始事件，与该资产的正常路径比较，再关联账户和时序；不需要 PoC、漏洞版本特征或 IOC。情报、Quake 暴露面和文章索引继续提供补充上下文。

这适合缩短新漏洞披露后尚缺少特征的响应准备窗口，但不能保证覆盖所有未知攻击。当前仍是日志导入 / CLI / API 批次分析工作台，没有常驻采集、实时消息推送或自动云脉管理服务。设计期准备的内容在分析发生时发挥作用，不等于已经在业务网执行预防控制。

## 已实现的模型

| 模型 | 判定与证据 | ATT&CK 关联 |
| --- | --- | --- |
| B101 | 登记资产作为网络源，访问配置的内部网络远程服务；目标网段、端口、协议不匹配角色的批准路径。连接不证明远程登录成功。 | [T1021 Remote Services](https://attack.mitre.org/techniques/T1021/) |
| B102 | 同资产的基线外远程连接，在滑动窗口内达到不同目标数量门槛；默认 300 秒 / 3 个目标。重复连接同一目标不增加目标数。 | [T1021 Remote Services](https://attack.mitre.org/techniques/T1021/) |
| B103 | 成功的角色、权限或组变更，不匹配操作者、动作、目标账户与目标权限四元组。 | [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| B104 | 成功的权限提升，不匹配用户、目标身份及提权程序路径。 | [T1548 Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) |
| C101 | 同资产、精确相同的活动账户，先出现 B103/B104，再于 15 分钟内出现 B101。 | 关联上述权限变化与远程服务行为，仍需会话级因果核验 |

这是本项目的实验性行为分析实现与技术映射，不是 MITRE 对产品的认证或完整 ATT&CK 覆盖。尤其 B104 只提供需要核验的 T1548 相关线索，不凭一条提权结果就证明特定机制被滥用。B102 和 C101 每资产、每分析最多各输出一个满足条件的窗口/链，原始事件保留供继续排查。

## 开始使用

工作台进入“行为基线”，点击“无 IOC 行为演练”。演练包含 11 条日志、0 条 IOC，产生 7 条线索、1 个高风险事件。工作站存在异常权限变化与三个基线外远程目标；跳板机访问同类服务符合其角色批准路径。共有 6 条事件被识别为符合预期，未产生相应基线偏离告警。

```bash
python -m sentinel_zt behavior-demo --out output/behavior-demo
python -m sentinel_zt baseline-template --out private/baseline-policy.json
# 编辑、核验并审核草案后，再开启 enabled
python -m sentinel_zt baseline-check --policy private/baseline-policy.json
python -m sentinel_zt analyze --events private/events.jsonl \
  --policy private/baseline-policy.json --out output/investigation
```

`behavior-demo` 每次生成当前时间的合成材料。`examples/behavior-demo/` 是固定时间样例；历史样例的审核时间不会自动刷新。生产配置不能通过机械修改时间绕过复核。

网页可下载草案、上传 JSON 校验，然后点击“用于下一次日志分析”。校验只是结构与范围检查，不证明配置已经过真实审批；不会自动写入生产策略、重算旧调查或修改云脉。

## 配置与设计期审核

策略仍使用顶层 `schema_version: 1`，可选扩展为 `behavior_baselines` 和 `behavior_exceptions`。完整可运行示例见 `examples/baseline-policy-template.json` 与 `examples/behavior-demo/policy.json`。

每个资产在原 `assets` 注册表中填写：

```json
{
  "ips": ["192.0.2.10"],
  "role": "workstation",
  "baseline_profile": "workstation",
  "criticality": "normal",
  "response_enabled": false,
  "permissions": {}
}
```

角色来自已审核策略，不接受日志或 Quake 数据自报角色。`baseline_profile` 必须引用存在的同角色配置。关键资产仍拒绝自动本机处置，相关基线偏离增加 8 点研判优先级，最高 99；分数不是失陷概率。

一个 profile 包含 `enabled`、`revision`、`role`、`reviewed_by`、`valid_from`、`valid_until`，以及至少一个行为段。有效期最长 90 天，建议按变更与演练结果更频繁复核。模板默认未启用。`reviewed_by` 是人工审核记录，不是独立身份认证。

| 行为段 | 配置 |
| --- | --- |
| network | `internal_networks`、`remote_ports`、`allowed_flows`、`fanout_window_seconds`、`fanout_threshold` |
| allowed_flows 每项 | 精确组合 `dst_network`（规范 CIDR）、`dst_ports`、`transport`（tcp/udp）、`reason`；仅用于本资产向外的内部远程访问 |
| identity.allowed_changes 每项 | `actor`、`action`、`target_user`、`target_role`、`reason`；完整精确匹配 |
| privilege.allowed_transitions 每项 | `user`、`target_user`、`process`（完整路径）、`reason`；完整精确匹配 |

正常跳板路径和业务工作流只降低对应基线模型的告警，不关闭原有规则或 IOC 检测。若可信遥测明确记录 `authorized=false`，批准路径和例外都不能覆盖这条拒绝事实。认证成功也不能单独使权限变化变得符合基线。

日常建议把角色、网段、允许服务、授权主体、业务负责人、管理/取证通道、回滚要求作为上线评审材料；策略 revision 和完整 `policy_digest` 随调查保留。变更后重新审核，避免把长期漂移直接学习成“正常”。本版本不自动学习和激活基线，也不宣称正常路径绝不会被攻击者滥用。

## 需要的日志字段

全部事件需要带时区的 `timestamp`、注册资产键 `host` 与 `event_type`。原始字段由可信 EDR、网络传感器、身份平台或操作系统日志提供；工具本身不认证采集源。

| event_type | 必需的行为字段 | 语义 |
| --- | --- | --- |
| network | `src_ip`、`dst_ip`、`dst_port`、`transport`；关联链另需 `user` | 源 IP 必须登记在该 host；协议缺失不会猜成 TCP。只分析配置的内部网段与远程服务端口。 |
| identity | `actor`、`action`、`target_user`、`target_role`、`outcome` | action 为 role_grant / permission_grant / group_add；只有 outcome=success 作为成功变更。 |
| privilege | `user`、`action=elevate`、`target_user`、`process`、`outcome` | outcome=success 才作为成功提升；程序路径精确匹配，不只匹配 basename。 |

`outcome` 支持 success/failure/unknown。未知或缺失结果不能当作成功。身份字段区分大小写、要求精确一致；在上游将 SID、域账户或稳定 ID 统一，不能仅凭显示名推断同一主体。

C101 中，B103 使用获得权限的 `target_user`，B104 使用发起提升的 `user`，与后续网络事件的 `user` 精确关联。若采集端只提供提升后的有效用户而没有原活动账户，需上游规范化，否则该链可能不匹配。既有同资产时间链仍是关联假设，不替代取证。

Sysmon 的 Protocol、Suricata 的 proto 现在保留为 transport。身份和提权通过标准 JSONL 接入；本版没有直接实现 Windows Security EVTX、Linux auditd 或云脉身份审计采集器。nginx 日志本身不足以提供上述身份或提权证据。

## 临时例外

`behavior_exceptions` 每项必须精确指定 id、host、rule_id、match、valid_from、valid_until、reason、reviewed_by。最长 24 小时，分析时间和事件时间均须位于有效期。命中后保留例外 ID、事件 ID、原因与截止时间。

| rule_id | match 的全部必需字段 |
| --- | --- |
| B101 | src_ip、dst_ip、dst_port、transport |
| B103 | actor、action、target_user、target_role |
| B104 | user、action、target_user、process |

例外不接受通配符、CIDR 或缺失维度，不直接抑制 B102/C101。它只排除精确的底层预期事件；其他异常事件仍可成链。旧 `suppressions` 不接受 B101–B104/C101，避免用“整台主机关闭规则”代替有范围的例外。

## 覆盖与响应

未配置、草案、未生效或已过期的 profile 明确显示状态。登记但未收到日志的资产也出现在覆盖表；源地址不匹配、缺少协议、缺少身份结果、缺少事件类型都提示缺口。当前批次没出现某类事件，既可能是没有活动，也可能是采集不足，不能据此判断安全。

无 IOC 的高风险行为可以生成 manual_investigation 计划，并在用户/应用映射有效时生成云脉待审核交接单。分析员需要核验账户、应用、业务影响和管理通道，再到云脉执行最小范围临时限制，保留实际策略 ID、审批和恢复测试。没有调用真实云脉管理接口。

本机 nftables 自动封禁仍要求有效 IP IOC、完整近期行为、注册授权、短期签名审批和显式 `--live`。v0.3.0 把 IOC 有效期也绑定到动作，审批/执行重新检查；基线到期不能继续支持审批或交接。需要使用 v0.3.0 重新分析、生成和审批旧计划。

服务端预算保持轻量：最多 100 个 profile；每个配置列表最多 100 项；最多 100 个精确例外；分析仍受事件、finding、证据展开和案例体积限制。没有新增数据库服务、消息队列或模型调用依赖。
