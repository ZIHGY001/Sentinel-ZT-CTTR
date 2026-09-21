# 响应操作与恢复

## 适用范围

Linux 本机 nftables 对端 IP 封禁；仅 input/output 链，既限制该 IP 入站，也限制本机向该 IP 出站。不改变其他规则表，不使用全局 flush，不自动清除连接跟踪，不处理转发流量/远程 EDR/云安全组/IdP。

工具不是完整企业零信任平台：策略判定和响应执行是其两个局部组件。OS 账户、响应密钥、策略文件及资产登记是本地信任根；共享 HMAC 密钥不是独立双人审批。

## 从研判到执行

1. 在目标端点以非特权身份分析，核验真实日志和情报。编辑私有 policy 的资产 IP、local_hostname、管理通道 protected_networks、operators；关键业务系统保持 criticality=critical。
2. 在 `plan.json` 中核对 host、peer_ip、evidence_ids、last_evidence_at、风险理由和业务影响。public 示例全部是假数据，不能用来作生产封禁依据。
3. 由目标端点的授权操作账户持有私有签名密钥。真实执行要求 Linux root；签名与执行应使用相同受控 OS 账户，使权限检查成立。密钥不提供给 FastAPI/Pi。

```bash
python -m sentinel_zt keygen --out private/response.key
python -m sentinel_zt approve --plan output/incident/plan.json \
  --action ACTION_ID --policy private/policy.json --operator AUTHORIZED_OPERATOR \
  --key private/response.key --out private/approval.json
```

上面的 ACTION_ID、AUTHORIZED_OPERATOR 必须替换为计划中真实 ID 与策略中操作员名称。签名绑定**整个计划**，计划绑定策略摘要；改动计划、动作、策略都须重新分析与授权。授权最长300秒，计划最长900秒（默认600秒）；应用时再次检查对端证据年龄。

4. 预览（不会调用 nft，也不会创建执行状态目录）：

```bash
python -m sentinel_zt apply --plan output/incident/plan.json \
  --approval private/approval.json --policy private/policy.json \
  --key private/response.key --state private/response-state --local-asset ASSET_ID
```

5. 仅在受控目标本机，明确加 `--live` 执行。同一 action ID 禁止重放。

```bash
python -m sentinel_zt apply --plan output/incident/plan.json \
  --approval private/approval.json --policy private/policy.json \
  --key private/response.key --state private/response-state --local-asset ASSET_ID --live
```

## 超时、审计与回滚

每个动作 `create table inet szt_<action>`，专属表名、ownership comment、内核 timeout set，默认300秒且不超过策略允许上限。TTL 到期后元素消失，封禁自动失效；空表会留下，需要通过回滚清理。已有同名表导致 create 失败，绝不接管已有表。

```bash
python -m sentinel_zt audit --key private/response.key --state private/response-state
python -m sentinel_zt rollback --action ACTION_ID --key private/response.key \
  --state private/response-state --local-asset ASSET_ID
# 检查输出后显式加 --live 才删除该动作的表。
```

回滚需要当前 OS 账户及密钥，验证本地回执与带 HMAC 的审计意图一致，并确认 nft 表的 ownership comment；只删除该动作的表。不在 HTTP 或 Agent 中暴露回滚工具。

应用采用本地排他锁串行化，先持久化 intent，再 nft --check 和执行。崩溃可能留下 pending；超时或异常标记 uncertain，因为命令返回失败不证明内核未完成事务。此时先 `nft list table inet szt_<id>` 检查，保留审计材料，按单动作回滚；不要反复执行同一授权。不存在或无法读取的表不被自动认定为已回滚，需人工确认。

审计链能检测修改/中间删除；没有外部锚定时，不能检测完整替换或尾部截断。将 audit 返回的 head_mac 定期保存到独立受控系统。主机 root 或持有 HMAC key 的攻击者不在此本地防篡改机制的保护范围内。

## 验证环境

当前交付的 nft 语法按官方文档生成，执行与回滚路径用模拟执行器验证，尚未在真实 nftables 网络命名空间验证。上线前应在隔离 Linux 网络命名空间核验 IPv4/IPv6、已建立会话、管理通道、内核 TTL、不同 nft 版本、失败恢复和业务连通性；未通过前保持 dry-run。


## v0.2.1 执行时效

响应日志锁忙时立即拒绝，需重新核验审批后重试。获取锁后以及 nftables `--check` 预检完成后，都使用当前时间重新校验审批、计划和证据。预检失败或审批在预检期间过期时记录 `not_applied`，不会发出变更请求；实际执行阶段超时或出错仍标记 `uncertain`，需要人工核实。升级后旧案例不会自动重算，使用新版本重新导入日志、生成计划和审批。
