import React, {useEffect, useState} from 'react';
import {Activity, Download, FileJson, Play, Shield, Check} from 'lucide-react';

const statuses = {active:'审核有效',draft:'草案未启用',expired:'审核已过期',not_yet_valid:'尚未生效',unconfigured:'未配置'};
const gaps = {
  reviewed_active_baseline_required:'缺少有效的已审核基线', event_outside_baseline_validity:'部分日志不在基线有效期内',
  network_fields_missing:'网络日志缺少源、目标、端口或协议', network_source_not_registered_asset:'网络源地址与资产登记不一致',
  network_transport_unknown:'网络协议未知', identity_change_fields_missing:'身份日志缺少操作者、目标权限或结果',
  privilege_fields_missing:'提权日志缺少主体、程序或结果', network_telemetry_absent:'未收到网络遥测',
  identity_telemetry_absent:'未收到身份变更遥测', privilege_telemetry_absent:'未收到权限提升遥测',
  no_evaluable_behavior_events:'没有足够字段的行为事件',
};
const reasons = {remote_flow_not_expected:'目标、端口或协议不在该资产角色的批准路径内',
  remote_fanout_threshold_exceeded:'短时基线外远程访问达到不同目标数门槛',identity_change_not_expected:'操作者、目标账户与权限组合不在批准路径内',
  privilege_transition_not_expected:'用户、目标身份与提权程序不在批准路径内',privilege_then_lateral_same_account:'同账户权限变化后出现横向访问偏离'};

export default function Baselines({api, current, task, saveJSON, readFile, onDemo, onUsePolicy, busy}) {
  const [models,setModels]=useState([]),[error,setError]=useState(''),[checked,setChecked]=useState(null),[config,setConfig]=useState(null);
  useEffect(()=>{let active=true;api('/behavior/models').then(r=>{if(active)setModels(r.models)}).catch(e=>{if(active)setError(e.message)});return()=>{active=false}},[]);
  const context=current?.analysis?.behavior_baseline;
  const assets=context?.assets||[];
  const deviations=(current?.analysis?.findings||[]).filter(f=>f.baseline);
  const loadPolicy=async text=>{setChecked(null);setConfig(null);const value=JSON.parse(text);const result=await api('/baselines/validate',{policy_config:value});setConfig(value);setChecked(result)};
  return <>
    {error&&<div className="error">{error}</div>}
    <section className="baseline-intro panel">
      <div><span className="eyebrow">DESIGN BEFORE INCIDENT</span><h2>先定义正常行为，再检测偏离</h2><p>以资产角色和批准路径固化行为模型。没有 IOC，也能发现横向访问和异常权限变化；基线与日志需要持续复核。</p></div>
      <button className="primary" disabled={busy} onClick={onDemo}><Play size={15}/>无 IOC 行为演练</button>
    </section>
    <div className="baseline-workflow">{['定义资产角色与正常路径','审核基线和限时例外','关联偏离及原始证据','核验后限制最小访问范围'].map((s,i)=><div key={s}><span>{i+1}</span>{s}</div>)}</div>
    <section className="panel form-panel">
      <div className="panel-head borderless"><div><h2>设计期基线配置</h2><p className="subtle">模板默认未启用。填入真实资产、审核人与有效期后，再随日志加载；校验不会修改现有调查或云脉策略。</p></div><div className="baseline-buttons">
        <button className="secondary" disabled={busy} onClick={()=>task(async()=>saveJSON('Sentinel-ZT-CTTR-baseline-policy.json',await api('/baselines/template')))}><Download size={15}/>下载基线模板</button>
        <label className="file-button"><FileJson size={15}/>校验策略 JSON<input type="file" accept=".json" disabled={busy} onChange={e=>readFile(e.target.files[0],loadPolicy)}/></label>
      </div></div>
      {checked&&<div className="baseline-checked"><p><Check size={16}/>结构校验通过 · {checked.profiles.length} 个基线 · {checked.bound_assets} 个绑定资产 · {checked.exception_count} 个限时例外</p>
        <p className="subtle">{checked.profiles.map(p=>`${p.name}：${statuses[p.status]}`).join('；')||'当前策略未配置行为基线'}</p>
        <button className="secondary" disabled={busy} onClick={()=>onUsePolicy(config)}>用于下一次日志分析</button>
      </div>}
    </section>
    <div className="baseline-models">{models.map(m=><section className="panel baseline-model" key={m.id}>
      <div className="baseline-model-head"><span className="rule-code">{m.id}</span><span className="status-tag">无需 IOC</span></div>
      <h3>{m.title}</h3><p>{m.rationale}</p><div className="techniques">{m.attack.map(t=><a key={t} href={'https://attack.mitre.org/techniques/'+t.replace('.','/')+'/'} target="_blank" rel="noreferrer">{t}</a>)}</div>
    </section>)}</div>
    <section className="panel"><div className="panel-head"><h2>当前调查的基线覆盖</h2><span className="subtle">{assets.filter(a=>a.status==='active').length} / {assets.length} 个资产基线有效</span></div>
      {!current?<div className="quiet-empty">运行无 IOC 行为演练，或导入带基线策略的日志。</div>:!context?<div className="quiet-empty">历史调查未计算基线覆盖，请重新分析原始日志。</div>:<div className="table-scroll"><table><thead><tr><th>资产 / 角色</th><th>基线状态</th><th>行为结果</th><th>覆盖缺口</th></tr></thead><tbody>{assets.map(a=><tr key={a.host}>
        <td>{a.host}<small>{a.role||'角色未知'} · {a.criticality==='critical'?'关键资产':'常规或待核验资产'}</small></td>
        <td>{statuses[a.status]}<small>{a.profile||'未绑定'}{a.revision?' / '+a.revision:''}</small></td>
        <td>{a.deviations} 条偏离<small>{a.expected_events} 条符合预期 · {a.exception_events} 条命中例外</small></td>
        <td>{a.gaps.length?a.gaps.map(g=>gaps[g]||g).join('；'):'当前输入未发现字段缺口'}<small>未告警不等于已确认安全</small></td>
      </tr>)}</tbody></table></div>}
    </section>
    <section className="panel baseline-evidence"><div className="panel-head"><h2>行为偏离与证据链 <span>{deviations.length}</span></h2><Activity size={18}/></div>
      {deviations.map(f=><details className="evidence" key={f.id}><summary><span className="rule-code">{f.rule_id}</span><strong className="evidence-title">{f.title}<small>{f.host}</small></strong><span>{f.score}</span></summary><div className="evidence-detail">
        <p>{reasons[f.baseline.reason]||f.baseline.reason}</p><p className="subtle">基线：{f.baseline.profile} / {f.baseline.revision} · 误报核验：{f.false_positives}</p>
        <pre>{JSON.stringify({observed:f.baseline.observed,evidence_ids:f.evidence_ids},null,2)}</pre>
        <p>核对原始日志、账户和业务变更后，可转入云脉页面生成指定用户到应用的待审核交接单。</p>
      </div></details>)}
      {!deviations.length&&<div className="quiet-empty">当前调查没有基线偏离线索；请同时检查覆盖缺口。</div>}
    </section>
    {!!context?.exceptions_applied?.length&&<section className="panel form-panel"><h2>本次命中的限时例外</h2><pre className="baseline-json">{JSON.stringify(context.exceptions_applied,null,2)}</pre></section>}
    <div className="response-note"><Shield size={18}/><div><strong>例外有范围，处置有期限</strong><p>基线仅在审核有效期内使用。临时例外精确绑定资产与行为，最长 24 小时，不屏蔽其他规则或 IOC 命中。行为告警可进入人工云脉交接；本页不会执行访问策略。</p></div></div>
  </>;
}
