import React, {useEffect, useState} from 'react';
import {BookOpen, Download, RefreshCw, Shield} from 'lucide-react';

const states={pending:'待检查',suspicious:'发现异常',not_observed:'已核验未见异常',needs_data:'缺少证据',not_applicable:'不适用'};
const platforms={unknown:'系统类型待确认',linux:'Linux',windows:'Windows'};
function SourceLinks({sources,ids}){return <div className="runbook-sources">{sources.filter(s=>!ids||ids.includes(s.id)).map(s=><a key={s.id} href={s.url} target="_blank" rel="noreferrer">{s.title} ↗</a>)}</div>}

function CheckEditor({check,document,onSave,busy,sources}){
  const previous=check.review;
  const [state,setState]=useState(check.status),[reviewer,setReviewer]=useState(previous?.reviewer||''),[observation,setObservation]=useState(previous?.observation||'');
  const [ids,setIds]=useState(previous?.evidence_ids||[]),[artifacts,setArtifacts]=useState(previous?.artifacts||[]);
  function updateArtifact(index,key,value){setArtifacts(a=>a.map((item,i)=>i===index?{...item,[key]:value}:item))}
  const saved=()=>onSave(check.id,{expected_revision:document.revision,status:state,reviewer,observation,evidence_ids:ids,
    artifacts:artifacts.map(({name,sha256,collected_at})=>({name,sha256,collected_at}))});
  return <details className="evidence runbook-check"><summary><span className="rule-code">{check.id}</span><strong className="evidence-title">{check.title}</strong><span className={'runbook-state '+check.status}>{states[check.status]}</span></summary>
    <div className="evidence-detail">
      <p>{check.objective}</p><h3>需要的证据</h3><ul>{check.evidence_required.map(x=><li key={x}>{x}</li>)}</ul>
      <p className="runbook-caution">{check.interpretation}</p>
      {!!check.commands.length&&<><h3>只读命令参考 · 请在授权目标人工使用</h3><pre>{check.commands.join('\n')}</pre><p className="subtle">命令不由工作台执行；时间窗、权限和工具可用性须按现场调整。不要将输出中的凭据录入备注。</p></>}
      <SourceLinks sources={sources} ids={check.source_ids}/>
      <div className="runbook-form">
        <div className="two-fields"><label>核验结果<select aria-label={'核验结果 '+check.id} value={state} onChange={e=>setState(e.target.value)}>{Object.entries(states).map(([v,l])=><option key={v} value={v}>{l}</option>)}</select></label>
          <label>记录人（自行填写）<input aria-label={'记录人 '+check.id} maxLength={100} value={reviewer} onChange={e=>setReviewer(e.target.value)}/></label></div>
        <label>核验依据与仍缺失的证据<textarea aria-label={'核验依据 '+check.id} rows={3} maxLength={2000} value={observation} onChange={e=>setObservation(e.target.value)}/></label>
        <label>关联当前事件证据（可多选）<select aria-label={'关联证据 '+check.id} multiple size={Math.min(4,document.available_evidence.length+1)} value={ids} onChange={e=>setIds(Array.from(e.target.selectedOptions,o=>o.value))}>
          {document.available_evidence.slice(0,200).map(e=><option key={e.id} value={e.id}>{e.timestamp} · {e.event_type} · {e.id}</option>)}
        </select></label>
        {document.available_evidence.length>200&&<p className="subtle">显示前 200 条；请拆分调查以便逐项复核。</p>}
        <div className="runbook-artifacts"><h3>外部证据登记（可选，文件另行保管）</h3>
          {artifacts.map((a,i)=><div className="runbook-artifact" key={i}>
            <label>名称<input aria-label={'证据名称 '+check.id+' '+i} maxLength={200} value={a.name} onChange={e=>updateArtifact(i,'name',e.target.value)}/></label>
            <label>SHA256<input aria-label={'证据哈希 '+check.id+' '+i} maxLength={64} value={a.sha256} onChange={e=>updateArtifact(i,'sha256',e.target.value)}/></label>
            <label>采集时间（含时区）<input placeholder="2026-09-22T10:00:00Z" value={a.collected_at} onChange={e=>updateArtifact(i,'collected_at',e.target.value)}/></label>
            <button className="secondary" disabled={busy} onClick={()=>setArtifacts(arr=>arr.filter((_,j)=>i!==j))}>移除此登记</button>
          </div>)}
          <button className="secondary" disabled={busy||artifacts.length>=10} onClick={()=>setArtifacts(a=>[...a,{name:'',sha256:'',collected_at:''}])}>添加外部证据</button>
          <p className="subtle">哈希为人工提供，平台未读取文件或验证其真实性。</p>
        </div>
        <button className="primary" disabled={busy||!reviewer.trim()||!observation.trim()} onClick={saved}>保存复核记录</button>
        {previous&&<p className="subtle">已保存版次 {previous.revision} · {previous.recorded_at} · {previous.reviewer}</p>}
      </div>
    </div>
  </details>
}

export default function Runbooks({api,current,task,saveJSON,busy}){
  const [catalog,setCatalog]=useState(null),[worksheets,setWorksheets]=useState([]),[incident,setIncident]=useState(current?.analysis?.incidents?.[0]?.id||'');
  const [platform,setPlatform]=useState('unknown'),[query,setQuery]=useState(''),[error,setError]=useState('');
  useEffect(()=>{let alive=true;Promise.all([api('/runbooks'),current?api('/cases/'+current.id+'/runbooks'):Promise.resolve({worksheets:[]})]).then(([c,w])=>{if(alive){setCatalog(c);setWorksheets(w.worksheets)}}).catch(e=>{if(alive)setError(e.message)});return()=>{alive=false}},[]);
  const incidents=current?.analysis?.incidents||[];
  const worksheet=worksheets.find(w=>w.incident_id===incident);
  const selected=incidents.find(c=>c.id===incident);
  const books=(catalog?.runbooks||[]).filter(b=>!query||JSON.stringify(b).toLowerCase().includes(query.toLowerCase()));
  const update=w=>setWorksheets(all=>[...all.filter(x=>x.incident_id!==w.incident_id),w]);
  async function reload(){await task(async()=>{setWorksheets((await api('/cases/'+current.id+'/runbooks')).worksheets);setError('')})}
  async function save(check,payload){await task(async()=>update(await api('/cases/'+current.id+'/runbooks/'+incident+'/checks/'+check,payload)))}
  return <>
    {error&&<div className="error">{error}</div>}
    <section className="panel form-panel runbook-intro"><span className="eyebrow">INVESTIGATE · VERIFY · IMPROVE</span><h2>把排查经验转为有证据的调查记录</h2>
      <p>参考 NOP Team Linux 应急响应手册与 Bypass007 实战笔记。根据行为线索选择流程，补齐证据，再把复盘建议交给基线负责人审核。</p>
      <div className="baseline-workflow">{['确认系统与范围','逐项核验并补证','复核最小响应范围','提交基线改进建议'].map((s,i)=><div key={s}><span>{i+1}</span>{s}</div>)}</div>
    </section>
    <section className="panel form-panel">
      <h2>当前事件调查清单</h2>
      {!incidents.length?<p className="quiet-empty">先运行演练或导入日志。下方可浏览完整手册目录；目录不代表已完成检测。</p>:<>
        <div className="two-fields runbook-selectors"><label>事件 / 资产<select aria-label="调查事件" value={incident} onChange={e=>setIncident(e.target.value)}>{incidents.map(c=><option key={c.id} value={c.id}>{c.host} · 风险优先级 {c.risk}</option>)}</select></label>
          <label>人工确认的系统类型<select aria-label="系统类型" disabled={!!worksheet||busy} value={worksheet?.platform||platform} onChange={e=>setPlatform(e.target.value)}>{Object.entries(platforms).map(([v,l])=><option key={v} value={v}>{l}</option>)}</select></label></div>
        <p className="subtle">{selected?.rule_ids.join(' · ')} · 角色：{selected?.asset_profile?.role||'待核验'} · 系统类型保存后固定；不适用的检查需记录理由。</p>
        <div className="baseline-buttons">
          {!worksheet&&<button className="primary" disabled={busy} onClick={()=>task(async()=>update(await api('/cases/'+current.id+'/runbooks',{incident_id:incident,platform})))}><BookOpen size={15}/>建立调查清单</button>}
          <button className="secondary" disabled={busy} onClick={reload}><RefreshCw size={15}/>重新加载记录</button>
          {worksheet&&<><button className="secondary" onClick={()=>saveJSON('sentinel-investigation-checklist.json',worksheet)}><Download size={15}/>导出调查记录</button>
          <button className="secondary" onClick={()=>saveJSON('sentinel-baseline-review-tasks.json',worksheet.baseline_feedback)}><Download size={15}/>导出基线复盘建议</button></>}
        </div>
      </>}
    </section>
    {worksheet&&<>
      <div className="runbook-metrics">{[['检查项',worksheet.summary.total],['已复核 / 不适用',worksheet.summary.reviewed],['待检查 / 缺证',worksheet.summary.unresolved],['异常待处置',worksheet.summary.counts.suspicious]].map(([label,n])=><div key={label}><strong>{n}</strong><span>{label}</span></div>)}</div>
      <p className="subtle runbook-meta">清单版次 {worksheet.revision} · 手册 {worksheet.catalog_version} · 进度不代表安全评分；记录人为自行声明，非个人身份认证。</p>
      {worksheet.runbooks.map(b=><section className="panel" key={b.id}><div className="panel-head"><h2>{b.title}</h2><span className="subtle">{b.matched_rules.length?b.matched_rules.join(' / '):'基础核验'}</span></div>
        {worksheet.checks.filter(c=>c.runbook_id===b.id).map(c=><CheckEditor key={worksheet.incident_id+'/'+c.id+'/'+(c.review?.revision||0)} check={c} document={worksheet} onSave={save} busy={busy} sources={worksheet.sources}/>)}</section>)}
      <details className="panel form-panel"><summary>查看历次复核记录（{worksheet.history.length}）</summary><pre className="baseline-json">{JSON.stringify(worksheet.history,null,2)}</pre></details>
    </>}
    <section className="panel form-panel"><h2>手册目录与来源</h2><p className="subtle">目录包含 {catalog?.runbooks.length||0} 类流程。系统专用清单只有确认类型后才加入调查；这里只保存原创步骤与来源链接。</p>
      <input aria-label="搜索应急手册" placeholder="搜索 SSH、PAM、持久化、Web、证据…" value={query} onChange={e=>setQuery(e.target.value)}/>
      <div className="runbook-catalog">{books.map(b=><details key={b.id}><summary><strong>{b.title}</strong><span>{b.platform==='any'?'通用':platforms[b.platform]} · {b.checks.length} 项</span></summary>
        {b.checks.map(c=><div key={c.id}><h3>{c.id} · {c.title}</h3><p>{c.objective}</p><p className="subtle">{c.interpretation}</p><SourceLinks sources={catalog.sources} ids={c.source_ids}/></div>)}</details>)}</div>
      {catalog&&<p className="subtle">{catalog.command_notice}</p>}
    </section>
    <div className="response-note"><Shield size={18}/><div><strong>调查记录与处置授权分别审核</strong><p>没有采集到证据时选择“缺少证据”。本页不会执行命令、清理主机、修改风险分或允许列表；云脉处置仍需在原有流程中审核。</p></div></div>
  </>;
}
