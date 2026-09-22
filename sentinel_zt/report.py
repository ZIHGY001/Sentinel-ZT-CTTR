"""Offline HTML report. Every untrusted value is HTML escaped."""
import html
import json
from .common import atomic_write
from . import runbooks

MAX_REPORT_BYTES = 32 * 1024 * 1024


def esc(value):
    return html.escape(str(value), quote=True)


def render(analysis, plan, destination, worksheets=()):
    counts = analysis["statistics"]
    incidents = analysis["incidents"]
    cards, rows = [], []
    for case in incidents:
        rules = " · ".join(case["rule_ids"])
        cards.append(f'''<article class="case"><div class="case-head"><h3>{esc(case['host'])}</h3>
          <span class="tag {esc(case['severity'])}">{esc(case['severity'].upper())}</span></div>
          <div class="risk">{case['risk']}<small> / 99</small></div>
          <div class="track"><i style="width:{case['risk']}%"></i></div>
          <p>{esc(rules)}</p><p class="muted">{len(case['evidence_ids'])} 条关联证据 · 待分析员核验</p></article>''')
    event_map = {e["id"]: e for e in analysis["events"]}
    evidence_bytes = 0
    for f in analysis["findings"]:
        evidence = [event_map[e] for e in f["evidence_ids"]]
        baseline = ('<h4>行为基线偏离</h4><pre>' + esc(json.dumps(f["baseline"], ensure_ascii=False, indent=2)) + '</pre>') if f.get("baseline") else ''
        rows.append(f'''<details class="finding"><summary><span class="code">{esc(f['rule_id'])}</span>
          <strong>{esc(f['title'])}</strong><span class="finding-host">{esc(f['host'])}</span>
          <b>{f['score']}</b></summary><div class="detail"><p>{esc(f['rationale'])}</p>
          <p class="muted">误报场景：{esc(f['false_positives'])}</p>
          <p>ATT&amp;CK：{esc(', '.join(f['attack']) or '未映射')} · {esc(f['verdict'])}</p>
          <h4>证据与来源</h4><pre>{esc(json.dumps(evidence, ensure_ascii=False, indent=2))}</pre>
          <h4>情报匹配</h4><pre>{esc(json.dumps(f['intel'], ensure_ascii=False, indent=2))}</pre>{baseline}</div></details>''')
        evidence_bytes += len(rows[-1].encode("utf-8"))
        if evidence_bytes > MAX_REPORT_BYTES:
            raise ValueError("report exceeds 32 MiB; split the investigation")
    action_rows = []
    for a in plan["actions"]:
        state = "需签名授权" if a["executable"] else "人工处理"
        detail = a.get("peer_ip") or "；".join(a.get("steps", []))
        gates = ", ".join(a.get("gates", []))
        action_rows.append(f"<tr><td>{esc(a['host'])}</td><td>{esc(a['type'])}</td><td>{esc(detail)}"
                           f"<small>{esc(gates)}</small></td><td>{esc(state)}</td></tr>")
    high = sum(c["risk"] >= 70 for c in incidents)
    planned = sum(a["executable"] for a in plan["actions"])
    content = '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>Sentinel-ZT-CTTR · 应急研判报告</title><style>
:root{--bg:#f3f5f7;--ink:#152536;--muted:#657585;--line:#dde4ea;--accent:#087f8c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
header{background:#102b3a;color:#f6fbff;padding:44px max(28px,calc((100vw - 1160px)/2));border-bottom:5px solid #40c5bd}
.eyebrow{font-size:12px;letter-spacing:3px;color:#79d9d3;font-weight:700}h1{font-size:34px;line-height:1.3;margin:12px 0}header p{color:#c3d4dc;max-width:820px;margin:12px 0 0}
main{max-width:1216px;padding:30px 28px 56px;margin:auto}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}.metric{background:white;border:1px solid var(--line);border-radius:12px;padding:18px 22px}.metric strong{display:block;font-size:30px;line-height:1.4}.metric span{color:var(--muted);font-size:13px}
.section-title{display:flex;justify-content:space-between;align-items:baseline;margin-top:34px}h2{font-size:21px;margin:0 0 16px}h3{font-size:17px;margin:0}h4{margin-bottom:8px}.muted{color:var(--muted);font-size:13px}.cases{display:grid;grid-template-columns:repeat(auto-fit,minmax(255px,1fr));gap:16px}.case{background:#fff;border:1px solid var(--line);border-radius:12px;padding:20px}.case-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.tag{padding:3px 8px;border-radius:5px;font-size:10px;font-weight:750;letter-spacing:1px;background:#eaf0f3}.critical{background:#ffebe9;color:#b02d27}.high{background:#fff0d9;color:#925a00}.medium{background:#dff2f3;color:#08656c}.risk{font-size:40px;font-weight:750;margin:14px 0 5px}.risk small{font-size:15px;color:var(--muted);font-weight:400}.track{height:5px;background:#e8edf1;border-radius:3px}.track i{height:100%;display:block;background:var(--accent);border-radius:3px}.case p{margin:12px 0 0;font-size:12px;overflow-wrap:anywhere}
.finding{margin-bottom:9px;background:#fff;border:1px solid var(--line);border-radius:8px}.finding summary{cursor:pointer;display:flex;gap:16px;align-items:center;padding:16px}.finding summary::before{content:'+';color:var(--accent);font-weight:bold}.finding[open] summary::before{content:'−'}.finding strong{flex:1;font-weight:600}.finding-host{font-size:12px;color:var(--muted)}.code{font:12px monospace;color:var(--accent);background:#e9f5f4;padding:3px 7px;border-radius:4px}.detail{padding:0 22px 20px;border-top:1px solid var(--line)}pre{font:12px/1.6 ui-monospace,monospace;white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7f9;padding:14px;border-radius:6px;max-height:400px;overflow:auto}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px;background:white}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;vertical-align:top;padding:14px;border-bottom:1px solid var(--line)}th{background:#eaf0f3;color:#456071;font-size:12px}td small{display:block;color:#a05c19;overflow-wrap:anywhere}td:nth-child(3){min-width:280px}.note{padding:17px 20px;background:#e5f2f3;border-left:3px solid var(--accent);margin:24px 0;font-size:13px}footer{font-size:12px;color:var(--muted);margin-top:30px;overflow-wrap:anywhere}
@media(max-width:650px){header{padding:28px 20px}h1{font-size:26px}main{padding:20px 16px}.metrics{grid-template-columns:repeat(2,1fr)}.finding summary{gap:8px;flex-wrap:wrap}.finding-host{display:none}.section-title{display:block}.metric{padding:14px}}
@media print{header{background:white;color:#152536;padding:15px 0}header p,.eyebrow{color:#456071}main{padding:12px 0}.finding{break-inside:avoid}.case{break-inside:avoid}.note{background:white}}
</style></head><body><header><div class="eyebrow">SENTINEL-ZT-CTTR / INCIDENT RESPONSE</div>
<h1>从行为证据，到有边界的响应。</h1><p>关联威胁情报、端点行为与访问上下文。每个结论都能追溯证据，每次处置都受授权、时效与资产范围约束。</p></header><main>'''
    content += '<div class="metrics">' + ''.join(
        f'<div class="metric"><strong>{esc(number)}</strong><span>{esc(label)}</span></div>'
        for number, label in [(counts['analyzed_events'], '已分析事件'), (len(analysis['findings']), '检测线索'),
                              (high, '高风险资产'), (planned, '可授权的处置计划')]) + '</div>'
    content += '<div class="section-title"><h2>资产研判</h2><span class="muted">风险分数为启发式排序，不是失陷概率</span></div><div class="cases">' + ''.join(cards) + '</div>'
    if not cards:
        content += '<p>未发现符合当前规则的异常；请同时检查日志覆盖率和排除统计。</p>'
    baseline_context = analysis.get("behavior_baseline")
    if baseline_context:
        content += '<div class="section-title"><h2>资产角色与基线覆盖</h2><span class="muted">无需 IOC；覆盖缺口不能解释为安全</span></div><pre>' + esc(json.dumps(
            {"assets": baseline_context["assets"], "exceptions_applied": baseline_context["exceptions_applied"]},
            ensure_ascii=False, indent=2)) + '</pre>'
    content += '<div class="section-title"><h2>行为与情报证据</h2><span class="muted">展开查看规则解释、误报场景和原始字段</span></div>' + ''.join(rows)
    content += '<div class="section-title"><h2>响应计划</h2><span class="muted">此报告没有执行任何处置</span></div><div class="table-wrap"><table><thead><tr><th>资产</th><th>动作</th><th>范围 / 下一步</th><th>状态</th></tr></thead><tbody>' + ''.join(action_rows) + '</tbody></table></div>'
    content += '<div class="section-title"><h2>调查手册与复核记录</h2><span class="muted">检查进度不等于安全证明；不会修改处置权限</span></div>'
    for case in incidents:
        titles = [r['title'] for r in runbooks.recommend(case)]
        content += '<p>' + esc(case['host']) + '：' + esc('；'.join(titles)) + '</p>'
    if not worksheets:
        content += '<p class="muted">尚无人工复核记录。可在应急手册页确认系统类型后建立调查清单。</p>'
    for worksheet in worksheets:
        summary = runbooks.summarize(worksheet)
        content += '<details class="finding"><summary>' + esc(worksheet['host']) + ' · 复核版次 ' + esc(worksheet['revision']) + ' · 待补证 ' + esc(summary['unresolved']) + '</summary><div class="detail"><pre>' + esc(json.dumps(worksheet, ensure_ascii=False, indent=2)) + '</pre><h4>待审核基线复盘建议</h4><pre>' + esc(json.dumps(runbooks.feedback(worksheet), ensure_ascii=False, indent=2)) + '</pre></div></details>'
    content += '<div class="note">零信任访问判定需由接入网关执行；本地防火墙适配器仅对指定对端实施有时限的入站、出站封禁。域名命中不自动扩展为整个云服务商封禁。</div>'
    content += f'<details><summary>数据质量与排除统计</summary><pre>{esc(json.dumps({"events":counts,"intel":analysis["intel_ignored"],"warnings":analysis.get("warnings",[])},ensure_ascii=False,indent=2))}</pre></details>'
    content += f'<footer>生成时间：{esc(analysis["generated_at"])}<br>策略摘要：{esc(analysis["policy_digest"])}<br>Sentinel-ZT-CTTR 0.4.0 · 本地离线报告 · 日志可能含敏感字段，请按事件材料管理。</footer></main></body></html>'
    if len(content.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("report exceeds 32 MiB; split the investigation")
    atomic_write(destination, content)
