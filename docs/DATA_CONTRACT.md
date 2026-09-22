# 数据契约

## 标准事件 JSONL

每个 LF / CRLF 物理行一个 JSON 对象；JSON 字符串中的 U+0085、U+2028、U+2029 不作为记录边界。单行预算按 UTF-8 字节计算。最多 10,000 条事件；CLI 单文件上限 64 MiB，单行 1 MiB；网页单日志文件 4 MB，API 请求总计 8 MiB。

```json
{"timestamp":"2026-09-20T11:59:00Z","host":"workstation-demo","event_type":"process_start","process":"C:\\Windows\\cmd.exe","parent_process":"C:\\Office\\WINWORD.EXE","user":"demo-user"}
```

| 字段 | 约束 / 含义 |
| --- | --- |
| timestamp | 必需，带时区 ISO 8601，统一转 UTC；未来事件不参与研判 |
| host | 必需，资产注册表的资产键；不能用采集器名冒充多个目标 |
| event_type | 必需，见下表 |
| src_ip / dst_ip | 可选，合法 IPv4/IPv6，不能是命令或任意字符串 |
| src_port / dst_port / status | 可选，非负整数，端口/状态须有明确来源 |
| process / parent_process | 可选，完整路径；引擎派生进程 basename |
| path / url / query | HTTP 原始请求字段；最多两层 URL 解码用于行为匹配，保留原值 |
| authenticated / authorized | 布尔值。必须来自可信认证/授权日志；缺失是未知，不能用字符串 "false" |
| approved / verified / webroot | 布尔值，需由变更库、签名验证或资产映射提供 |
| sha256 / sha1 / md5 / domain | 可选 IOC 比对字段；不从任意文本抓取再直接执行处置 |
| process_guid / parent_guid | 可选，供分析员进一步核验因果链；当前关联仅同资产 + 时间窗口 |

| event_type | 常用字段 |
| --- | --- |
| process_start | process、parent_process、process_guid |
| network | src_ip、dst_ip、dst_port、authorized |
| http | path、query、method、status、authenticated、product、uploaded_filename |
| dns | domain |
| file_write / file_read | file_path、webroot、approved 或 authorized |
| identity | action（account_create / role_grant / permission_grant / sso_update）、authorized |
| agent | action（skill_install / skill_modify）、verified；或 tool（shell / exec / read_secret / network_admin）、authorized |
| persistence | action（scheduled_task / service_create / cron_change / run_key）、approved |
| registry | registry_path |
| configuration | action=jdbc_url_change、approved |
| process_snapshot | 只读采集快照；不等同 process_start，不产生历史执行证据 |

内容摘要生成内部 event ID。外部 `id` 不用作可信去重键。每条导入事件记录输入文件名、行号和原始日志行 SHA256（UTF-8，移除文件开头 BOM，不含行终止符）；适配器转换前计算。内部合成事件使用规范 JSON 哈希。输入清单记录原始文件 SHA256。哈希能检查字节一致性，不能证明日志来源真实，也不是完整司法取证链。

## Sysmon / nginx / Suricata

Sysmon 支持 `Event.System` + `Event.EventData` 对象，或者 `System` + `EventData`；EventData 可以是键值映射或 `Data` 数组（@Name/#text 或 Name/Value）。支持 EventID 1、3、11、13、22。导出器若使用 `winlog.event_data` 等其他结构，应先转换。**不解析二进制 .evtx。**

Sysmon UtcTime 无时区后缀时按其字段定义视为 UTC；其他标准事件不得省略时区。EventID 1 的进程 HASH 可用于 IOC 匹配。nginx 仅支持 common/combined 单行格式；不以 HTTP 状态或头部推断认证成功。

Suricata 支持 http、dns、flow、tls、alert EVE 类型。网络字段通过显式资产 IP 注册表确定实际对端；无法确认端点归属时不生成可执行封禁。其他事件类型统计为 unsupported_events。

## 威胁情报

```json
{"indicators":[{"type":"ip","value":"203.0.113.50","source":"synthetic-training-feed","confidence":90,"valid_from":"2026-09-19T12:00:00Z","valid_until":"2026-09-21T12:00:00Z","revoked":false,"tlp":"CLEAR","tags":["synthetic"]}]}
```

置信度 0–100，来源必填，有效期必须显式。CSV 使用同一组字段名，列名必须唯一且每行列数一致；tags 用分号分隔。默认最低置信度 60。`revoked` 的相同 source/id 优先于旧记录。事件时间和分析时间都需要处于有效期内；这是一项保守本地策略，不是 STIX 对历史追溯的唯一解释。

支持 STIX Bundle 中的单一等值模式：ipv4-addr、ipv6-addr、domain-name、url、file hashes。AND/OR、正则、CIDR 模式、关系图、TAXII 拉取均未实现，显式返回跳过警告。缺少 valid_until 的 STIX Indicator 采用本地 30 天期限并提示。同一 ID/modified 的冲突表示整批拒绝；同批任意版本撤销后不被后续活动版本重新启用。不跨导入批次维护撤销数据库。解析同 Bundle 中附带的 TLP 标记并保留最高限制级别；未附标记默认 AMBER，无法解析、自定义或 granular 标记保守标为 RED 并提示人工检查原始分发约束。这不是完整 STIX 标记处理或分享策略执行器。

域名精确匹配（大小写、末尾点标准化），不按后缀泛化。URL 规范化 scheme/host/默认端口，保留路径与查询大小写，不提取凭证。域名命中不会解析并自动封禁共享云 IP。

## 零信任访问请求

`access` 命令接收 identity_verified、mfa_verified、device_managed、device_compliant、token_valid、posture_checked_at、subject、resource、action。它是供可信 PEP/IdP/EDR 接入的策略判定器；**这些字段不能直接相信外部客户端自行填报**。当前 UI 不将这个样例判定器当作真实企业 SSO。

返回 allow/step_up/deny。CLI 同时检查分析时效、当前策略摘要和请求资源的原始观测时间；没有新鲜资源遥测会报错，不产生允许结果。allow 默认仅租约 60 秒，PEP 必须在到期/风险变化时重新判定。高风险事件返回 deny，缺乏明确资源权限或过期设备状态返回 deny；网络位置不授予信任。


## v0.2.1 严格输入与资源预算

- JSON 拒绝重复键、NaN/Infinity、溢出为无穷的数字、无效 Unicode 与超过 64 层的嵌套。策略数值必须是 JSON 整数，权限必须是“主体 → 完整动作字符串数组”。
- `process_name`、`parent_process_name`、`path_normalized`、`query_normalized` 不接受外部覆盖，始终从原始字段派生。原始目标中的查询串与独立 `query` 不一致时拒绝导入。
- IP 必须是字符串，不接受数值型 IP 或 IPv6 `%zone`。受信资产注册表要求规范 IP 表示；IPv4 映射 IPv6 不进入自动封禁。
- 未上传策略时，API 使用空资产注册表。演练资产权限只用于显式的演练接口。
- 每次分析最多 10,000 条事件、10,000 条 IOC、20,000 条 finding、50,000 项证据/情报关联；同一 observable 最多 100 个来源/ID，IOC 命中展开最多 8 MiB。超预算明确报错，不返回部分成功结果。
- 单案例序列化结果最多 16 MiB，HTML 报告最多 32 MiB，单工作目录最多 500 个案例。达到案例上限后，停服务并归档整个私有工作目录，再使用新的私有工作目录；不要删除单独的数据库以绕过审计留存。
- 每进程最多同时处理 2 个写请求、1 个 Pi 请求；请求体总读取时间最多 15 秒。Pi 输入最多 512,000 字节。超额分别返回 429、408 或 413。
- 知识索引最多 10,000 条，网页检索词最多 512 字符。大调查应按时间窗口和资产范围拆分。

## v0.2.2 时效与交接单预算

- 自动响应和云脉交接要求同资产至少一个完整的新鲜 B 类行为 finding；其所有引用事件均须满足 `0 ≤ 当前时间 - 观测时间 < 时效上限`。C 类关联链里的新 IOC 不能刷新旧行为。聚合行为按最早引用事件计算时效。
- 计划新增 `behavior_rule_id`、`behavior_evidence_ids` 和 `behavior_evidence_at`，审批与执行按原始时间重新检查。旧计划须重新分析并审批。
- 云脉交接单的 `review_before` 受行为证据、映射和配置复核期限共同约束；总期限取可复核项目中的最早到期时间。
- 网页交接单最多保存 500 个 JSON 文件、总计 64 MiB；超额返回 409，保留已有材料。停服务并归档整个私有工作目录后再使用新目录，不自动删除旧交接记录。
- 抑制项的规则 ID、资产、原因及过期时间均须为非空字符串。UTC 转换/默认到期时间溢出、CSV 重名列、列数错位及无法安全解释的 STIX 撤销记录会明确拒绝。

## v0.3.0 行为基线扩展

策略可包含 `behavior_baselines` 与 `behavior_exceptions`，资产通过 `baseline_profile` / `role` 绑定。草案默认禁用，profile 有效期最长 90 天，精确例外最长 24 小时。完整字段与约束见 [行为基线指南](BEHAVIOR_BASELINES.md)。新增模型不能使用旧的整规则 `suppressions`。

标准事件增加字符串字段 `user`、`actor`、`target_user`、`target_role`、`transport`、`outcome`，各最长 512 字符。outcome 为 success/failure/unknown；transport 统一为小写，缺失或非 tcp/udp 不推断协议。Sysmon Protocol / EVE proto 保留到该字段。身份变更/权限提升仅在 success 且关键字段完整时判断。

分析输出新增 `behavior_baseline`（资产覆盖、预期活动计数、偏离数、缺口、命中例外与模型目录）；基线 finding 新增 `baseline`（profile、revision、valid_until、reason、observed、ioc_required）。incident 增加登记资产上下文，风险解释可含 `asset_priority`。Pi 自动摘要不包含新增的原始主体、角色名、IP 或 observed 数据。

`block_peer` 动作新增 `intel_evidence`，绑定匹配 IOC 的身份、来源、有效期和实际对端观测。审批及执行重新验证情报时效；旧计划必须重新生成。新增网页接口：GET `/api/behavior/models`、GET `/api/baselines/template`、POST `/api/baselines/validate`（policy_config 对象）、POST `/api/demo/behavior`；全部需要工作台鉴权。校验不会持久化或激活策略。
