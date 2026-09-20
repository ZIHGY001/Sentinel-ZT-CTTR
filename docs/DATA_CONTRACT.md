# 数据契约

## 标准事件 JSONL

每行一个 JSON 对象。最多 100,000 条事件；CLI 单文件上限 64 MiB，单行 1 MiB；网页单日志文件 4 MB，API 请求总计 8 MiB。

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

内容摘要生成内部 event ID。外部 `id` 不用作可信去重键。每条事件记录输入文件名、行号、规范 JSON 哈希；输入清单记录原始文件 SHA256。哈希能检查字节一致性，不能证明日志来源真实，也不是完整司法取证链。

## Sysmon / nginx / Suricata

Sysmon 支持 `Event.System` + `Event.EventData` 对象，或者 `System` + `EventData`；EventData 可以是键值映射或 `Data` 数组（@Name/#text 或 Name/Value）。支持 EventID 1、3、11、13、22。导出器若使用 `winlog.event_data` 等其他结构，应先转换。**不解析二进制 .evtx。**

Sysmon UtcTime 无时区后缀时按其字段定义视为 UTC；其他标准事件不得省略时区。EventID 1 的进程 HASH 可用于 IOC 匹配。nginx 仅支持 common/combined 单行格式；不以 HTTP 状态或头部推断认证成功。

Suricata 支持 http、dns、flow、tls、alert EVE 类型。网络字段通过显式资产 IP 注册表确定实际对端；无法确认端点归属时不生成可执行封禁。其他事件类型统计为 unsupported_events。

## 威胁情报

```json
{"indicators":[{"type":"ip","value":"203.0.113.50","source":"synthetic-training-feed","confidence":90,"valid_from":"2026-09-19T12:00:00Z","valid_until":"2026-09-21T12:00:00Z","revoked":false,"tlp":"CLEAR","tags":["synthetic"]}]}
```

置信度 0–100，来源必填，有效期必须显式。CSV 同名列，tags 用分号分隔。默认最低置信度 60。`revoked` 的相同 source/id 优先于旧记录。事件时间和分析时间都需要处于有效期内；这是一项保守本地策略，不是 STIX 对历史追溯的唯一解释。

支持 STIX Bundle 中的单一等值模式：ipv4-addr、ipv6-addr、domain-name、url、file hashes。AND/OR、正则、CIDR 模式、关系图、TAXII 拉取均未实现，显式返回跳过警告。缺少 valid_until 的 STIX Indicator 采用本地 30 天期限并提示。STIX 标记未完整解析，导入默认 AMBER，不自动公开分享。

域名精确匹配（大小写、末尾点标准化），不按后缀泛化。URL 规范化 scheme/host/默认端口，保留路径与查询大小写，不提取凭证。域名命中不会解析并自动封禁共享云 IP。

## 零信任访问请求

`access` 命令接收 identity_verified、mfa_verified、device_managed、device_compliant、token_valid、posture_checked_at、subject、resource、action。它是供可信 PEP/IdP/EDR 接入的策略判定器；**这些字段不能直接相信外部客户端自行填报**。当前 UI 不将这个样例判定器当作真实企业 SSO。

返回 allow/step_up/deny。allow 默认仅租约 60 秒，PEP 必须在到期/风险变化时重新判定。高风险事件返回 deny，缺乏明确资源权限或过期设备状态返回 deny；网络位置不授予信任。
