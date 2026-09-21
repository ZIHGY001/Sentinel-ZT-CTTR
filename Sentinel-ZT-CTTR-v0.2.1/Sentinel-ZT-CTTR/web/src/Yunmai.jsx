import React, {useEffect, useState} from 'react';
import {Shield, Check, Download, RefreshCw, LockKeyhole} from 'lucide-react';

export default function Yunmai({api, current, task, saveJSON}) {
  const [state,setState]=useState(null),[error,setError]=useState(''),[draft,setDraft]=useState(null);
  useEffect(()=>{let active=true;api('/integrations/yunmai').then(s=>{if(active)setState(s)}).catch(e=>{if(active)setError(e.message)});return()=>{active=false}},[]);
  const refresh=()=>task(async()=>{setState(await api('/integrations/yunmai'));setError('')});
  const generate=()=>task(async()=>setDraft(await api('/cases/'+current.id+'/yunmai-handoff',{})));
  return <>
    <div className="integration-banner"><div className="integration-logo"><Shield size={25}/></div><div><h3>云脉 SASE</h3><p>内网应用发布 · 访问策略交接 · 操作结果复核</p></div><span className="connection">租户连通性待验证</span></div>
    {error&&<div className="error">{error}</div>}
    <section className="panel form-panel"><div className="panel-head borderless"><div><h2>接入配置</h2><p className="subtle">这里显示本机配置，不代表云脉身份认证或策略已生效。</p></div><button className="secondary" onClick={refresh}><RefreshCw size={14}/>刷新</button></div>
      <div className="sase-config-grid"><div><span>部署方式</span><strong>{state?.deployment_mode==='yunmai'?'云脉后方部署':'本地工作台'}</strong></div><div><span>应用访问地址</span><strong>{state?.public_origin||'尚未配置 HTTPS 地址'}</strong></div><div><span>用户与应用映射</span><strong>{state?.mapping_configured?`${state.mapping_count} 项配置，生成时检查时效`:'未配置'}</strong></div></div>
      <div className="response-note sase-note"><LockKeyhole size={18}/><div><strong>云脉负责访问通道，工作台保留独立鉴权</strong><p>应急人员通过云脉客户端接入后，再使用工作台访问令牌。客户端连接状态和请求中的身份字段不能替代后端认证。</p></div></div>
    </section>
    <div className="agent-grid"><section className="panel form-panel"><h2>生成云脉处置交接单</h2><p className="subtle sase-copy">将当前调查关联到已核验的单个用户和具体应用，输出临时访问限制建议。分析员审核后在云脉控制台实施，并记录策略 ID 与审计回执。</p>
      <div className="context-strip">{current?`当前调查：${current.analysis.incidents.length} 个事件`:'先在事件研判中加载调查或演练数据'}</div>
      <p className="subtle sase-copy">交接单不会调用云脉管理接口。限制用户访问指定应用可能影响该用户的其他终端，需要核验业务影响。</p>
      <button className="primary" disabled={!current||!state?.mapping_configured} onClick={generate}><Shield size={15}/>生成待审核交接单</button>
      {draft&&<div className="sase-result"><div className="panel-head borderless"><h3>待审核 · 未提交云脉</h3><button className="secondary" onClick={()=>saveJSON('Sentinel-ZT-CTTR-yunmai-handoff.json',draft)}><Download size={14}/>导出 JSON</button></div><p className="subtle">复核截止：{new Date(draft.review_before).toLocaleString()} · 未执行任何云脉变更</p>
        {draft.items.map(item=><div className="sase-item" key={item.incident_id}><strong>{item.host}</strong><span className="status-tag">{item.status==='blocked'?'需补齐核验信息':'可交人工复核'}</span><p>{item.proposal?`用户 ${item.proposal.subject.ref} → ${item.proposal.application_refs.join('、')}；建议有效期 ${item.proposal.requested_duration_seconds} 秒`:(item.gates.includes('verified_user_application_mapping_required')?'缺少已核验的用户与应用映射':item.gates.includes('mapping_stale_or_future')?'映射时间过期或晚于当前时间':item.gates.includes('fresh_behavior_evidence_required')?'缺少近期行为证据':item.gates.join(' / '))}</p></div>)}
        <details className="offline"><summary>查看完整交接单</summary><pre>{JSON.stringify(draft,null,2)}</pre></details></div>}
    </section><section className="panel form-panel agent-boundaries"><h3>处置与恢复要求</h3>{['核验用户、终端及具体应用归属','保留工作台、取证和管理通道','变更前保存有效策略与审批依据','验证新连接和已有会话的实际效果','到期复核并保留云脉审计回执'].map(t=><p key={t}><Check size={16}/>{t}</p>)}<hr/><p className="subtle">现有 SDK 操作当前客户端。自动修改租户策略、强制断开其他终端和审计日志拉取，仍需正式管理 API 联调。</p></section></div>
  </>;
}
