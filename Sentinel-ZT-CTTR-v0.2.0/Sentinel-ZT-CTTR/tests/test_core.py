import copy
import json
import os
import socket
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from sentinel_zt import assets, demo, engine, events, intel, knowledge, policy, report, response
from sentinel_zt.common import digest, iso, timestamp
from sentinel_zt.rules import detect, get_rules

NOW = timestamp("2026-09-20T12:00:00Z")


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.rows, ti, self.cfg, self.request = demo.fixtures(NOW)
        self.ev = [events.canonical_event(x, "test", i+1) for i,x in enumerate(self.rows)]
        self.iocs = [intel.Indicator.parse(x) for x in ti]

    def analysis(self, ev=None, ti=None):
        return engine.analyze(self.ev if ev is None else ev, self.iocs if ti is None else ti, NOW, self.cfg)

    def plan(self):
        self.cfg["assets"]["workstation-demo"]["local_hostname"] = socket.gethostname()
        a = self.analysis()
        p = engine.make_plan(a, self.cfg, NOW)
        act = next(x for x in p["actions"] if x["type"] == "block_peer" and x["host"] == "workstation-demo")
        return p, act


class IntelTests(Fixture):
    def test_domain_boundary_exact(self):
        idx = intel.IntelIndex(self.iocs, NOW)
        e = dict(self.ev[0], domain="evil-updates.example.test")
        self.assertEqual(idx.match(e), [])
        e["domain"] = "UPDATES.EXAMPLE.TEST."
        self.assertEqual(len(idx.match(e)), 1)

    def test_expired_future_revoked_low_confidence(self):
        original = self.iocs[0].__dict__
        rows = [{**original, "valid_until": iso(NOW)}, {**original,"valid_from":iso(NOW+timedelta(hours=1))},
                {**original,"revoked":True}, {**original,"id":"low","confidence":20}]
        # Different source/IDs, so revocation does not shadow other test categories.
        rows = [{**x,"id":str(i)} for i,x in enumerate(rows)]
        index = intel.IntelIndex([intel.Indicator.parse(x) for x in rows], NOW)
        self.assertEqual(index.ignored, {"expired":1,"future":1,"revoked":1,"low_confidence":1})
        self.assertFalse(index.index)

    def test_revocation_wins_across_feeds(self):
        revoked = intel.Indicator.parse({**self.iocs[0].__dict__,"revoked":True})
        index = intel.IntelIndex([self.iocs[0], revoked], NOW)
        self.assertFalse(index.index)

    def test_duplicate_feed_not_inflating_hits(self):
        idx = intel.IntelIndex([*self.iocs,*self.iocs], NOW)
        self.assertEqual(len(idx.match(self.ev[3])),1)

    def test_invalid_hash_rejected(self):
        with self.assertRaises(ValueError):
            intel.normalize("sha256", "a"*63)

    def test_url_preserves_case_sensitive_path(self):
        self.assertEqual(intel.normalize("url","HTTPS://Example.test:443/AbC#x"),"https://example.test/AbC")

    def test_stix_skips_compound_patterns(self):
        p = self.root / "stix.json"
        objs = [{"type":"indicator","id":"indicator--test","modified":iso(NOW),"pattern_type":"stix",
                 "pattern":"[ipv4-addr:value = '203.0.113.50']","valid_from":iso(NOW-timedelta(days=1))},
                {"type":"indicator","id":"indicator--bad","modified":iso(NOW),"pattern_type":"stix",
                 "pattern":"[ipv4-addr:value = '203.0.113.50' OR ipv4-addr:value = '203.0.113.51']",
                 "valid_from":iso(NOW-timedelta(days=1))}]
        p.write_text(json.dumps({"type":"bundle","objects":objs}))
        items, warnings = intel.load_intel(p)
        self.assertEqual(len(items),1)
        self.assertEqual(len(warnings),2)

    def test_event_time_validity(self):
        idx = intel.IntelIndex(self.iocs, NOW)
        e = dict(self.ev[3], timestamp=iso(NOW-timedelta(days=2)))
        self.assertEqual(idx.match(e),[])


class EventTests(Fixture):
    def test_requires_timezone(self):
        with self.assertRaises(ValueError):
            timestamp("2026-09-20T12:00:00")

    def test_unknown_auth_not_false(self):
        e = events.canonical_event({"timestamp":iso(NOW),"host":"h","event_type":"http",
                                   "path":"/kubepi/api/v1/sso","status":200},"x",1)
        self.assertNotIn("B006", [x["id"] for x in detect(e,get_rules())])

    def test_string_false_rejected(self):
        with self.assertRaises(ValueError):
            events.canonical_event(dict(self.rows[0], authenticated="false"),"x",1)

    def test_nginx_no_auth_inference(self):
        row = events.nginx('198.51.100.20 - - [20/Sep/2026:12:00:00 +0000] "GET /health HTTP/1.1" 200 15 "-" "Demo"',"web")
        self.assertEqual(row["host"],"web")
        self.assertNotIn("authenticated",row)

    def test_sysmon_parent_child(self):
        row={"Event":{"System":{"EventID":1,"Computer":"win"},"EventData":{"UtcTime":"2026-09-20 11:59:00.000",
             "Image":"C:\\Windows\\cmd.exe","ParentImage":"C:\\Office\\WINWORD.EXE"}}}
        ev=events.canonical_event(events.sysmon(row),"sysmon",1)
        self.assertIn("B001",[r["id"] for r in detect(ev,get_rules())])

    def test_suricata_requires_endpoint(self):
        with self.assertRaises(ValueError):
            events.eve({"event_type":"flow"},None)

    def test_repeated_event_dedup(self):
        p=self.root/'events.jsonl'
        p.write_text('\n'.join(json.dumps(self.rows[0]) for _ in range(3)))
        ev, manifest, stats=events.load_events([p])
        self.assertEqual(len(ev),1)
        self.assertEqual(stats['duplicates'],2)
        self.assertEqual(len(manifest[0]['sha256']),64)

    def test_double_encoded_traversal(self):
        e=events.canonical_event({'timestamp':iso(NOW),'host':'h','event_type':'http',
                                 'path':'/index.php/Pan/Public/download?path=%252e%252e%252fconfig'},'x',1)
        self.assertIn('B009',[r['id'] for r in detect(e,get_rules())])

    def test_nonmatching_event_id_not_trusted(self):
        a=events.canonical_event(dict(self.rows[0],id='same'),'x',1)
        b=events.canonical_event(dict(self.rows[1],id='same'),'x',2)
        self.assertNotEqual(a['id'],b['id'])


class DetectionTests(Fixture):
    def test_demo_has_three_risky_assets_clean_excluded(self):
        a=self.analysis()
        self.assertEqual({c['host'] for c in a['incidents']},{'workstation-demo','web-demo','agent-demo'})
        self.assertTrue(all(c['risk']>=85 for c in a['incidents']))
        self.assertTrue({'C001','C002','C003','C004','B018'}.issubset({f['rule_id'] for f in a['findings']}))

    def test_ioc_only_never_executable(self):
        a=self.analysis([self.ev[3]])
        p=engine.make_plan(a,self.cfg,NOW)
        self.assertFalse(any(x['executable'] for x in p['actions']))

    def test_cross_asset_not_correlated(self):
        e=copy.deepcopy(self.ev[3]);e['host']='other'
        a=self.analysis([self.ev[0],e])
        self.assertFalse(any(f['rule_id'].startswith('C') for f in a['findings']))

    def test_reverse_time_not_correlated(self):
        e=copy.deepcopy(self.ev[3]);e['timestamp']=iso(NOW-timedelta(seconds=700))
        a=self.analysis([self.ev[0],e])
        self.assertNotIn('C001',{f['rule_id'] for f in a['findings']})

    def test_stale_future_events_excluded(self):
        old=dict(self.ev[0],timestamp=iso(NOW-timedelta(days=2)))
        future=dict(self.ev[1],timestamp=iso(NOW+timedelta(seconds=1)))
        a=self.analysis([old,future])
        self.assertEqual(a['statistics']['analyzed_events'],0)
        self.assertEqual(a['statistics']['stale_events'],1)
        self.assertEqual(a['statistics']['future_events'],1)

    def test_critical_asset_never_executable(self):
        self.cfg['assets']['workstation-demo']['criticality']='critical'
        p=engine.make_plan(self.analysis(),self.cfg,NOW)
        self.assertFalse(any(x['executable'] for x in p['actions'] if x['host']=='workstation-demo'))

    def test_protected_peer_never_executable(self):
        self.cfg['protected_networks'].append('203.0.113.0/24')
        p=engine.make_plan(self.analysis(),self.cfg,NOW)
        self.assertFalse(any(x['executable'] for x in p['actions']))

    def test_domain_only_no_ip_block(self):
        ti=[x for x in self.iocs if x.type=='domain']
        p=engine.make_plan(self.analysis(ti=ti),self.cfg,NOW)
        self.assertFalse(any(x['type']=='block_peer' for x in p['actions']))

    def test_expiring_suppression(self):
        self.cfg['suppressions']=[{'rule_id':'B001','host':'workstation-demo','reason':'approved macro','expires_at':iso(NOW+timedelta(hours=1))}]
        self.assertNotIn('B001',{f['rule_id'] for f in self.analysis()['findings']})
        self.cfg['suppressions'][0]['expires_at']=iso(NOW)
        self.assertIn('B001',{f['rule_id'] for f in self.analysis()['findings']})

    def test_html_escapes_untrusted_data(self):
        self.ev[0]['host']='<script>alert(1)</script>'
        a=self.analysis();p=engine.make_plan(a,self.cfg,NOW)
        file=self.root/'report.html';report.render(a,p,file)
        text=file.read_text()
        self.assertNotIn('<script>alert(1)</script>',text)
        self.assertIn('&lt;script&gt;',text)


class ResponseTests(Fixture):
    def setUp(self):
        super().setUp();self.key=b'x'*32

    def token(self,p,a):
        return response.approve(p,a['id'],self.cfg,'lab-analyst',self.key,NOW)

    def test_approval_binds_full_plan(self):
        p,a=self.plan();token=self.token(p,a);p['actions'][0]['host']='changed'
        with self.assertRaises(ValueError):response.verify_approval(p,token,self.cfg,self.key,NOW)

    def test_expired_approval_rejected(self):
        p,a=self.plan();token=self.token(p,a)
        with self.assertRaises(ValueError):response.verify_approval(p,token,self.cfg,self.key,NOW+timedelta(seconds=300))

    def test_policy_changed_rejected(self):
        p,a=self.plan();self.cfg['response_threshold']=80
        with self.assertRaises(ValueError):response.validate_action(p,a,self.cfg,NOW)

    def test_unauthorized_operator(self):
        p,a=self.plan()
        with self.assertRaises(ValueError):response.approve(p,a['id'],self.cfg,'intruder',self.key,NOW)

    def test_dry_run_does_not_call_runner(self):
        p,a=self.plan();calls=[]
        result=response.apply(p,self.token(p,a),self.cfg,self.key,NOW,self.root/'state','workstation-demo',runner=lambda *a,**kw:calls.append(a))
        self.assertEqual(result['status'],'dry_run');self.assertEqual(calls,[])
        self.assertFalse((self.root/'state').exists())

    def test_wrong_host_rejected(self):
        p,a=self.plan()
        with self.assertRaises(ValueError):response.apply(p,self.token(p,a),self.cfg,self.key,NOW,self.root/'state','other')

    def test_ipv6_nft_and_timeout(self):
        p,a=self.plan();a['peer_ip']='2001:db8::10'
        script=response.render_nft(a)
        self.assertIn('ipv6_addr',script);self.assertIn('timeout 300s',script)
        self.assertNotIn('flush ruleset',script);self.assertNotIn('hook forward',script)

    def test_injected_ip_rejected(self):
        p,a=self.plan();a['peer_ip']='203.0.113.50; flush ruleset'
        with self.assertRaises(ValueError):response.render_nft(a)

    def test_apply_replay_and_rollback(self):
        p,a=self.plan();t=self.token(p,a);state=self.root/'state';calls=[]
        runner=lambda script,check=False:calls.append((script,check))
        with patch('sentinel_zt.response.require_root'):
            with patch('sentinel_zt.response.Journal',wraps=response.Journal):
                result=response.apply(p,t,self.cfg,self.key,NOW,state,'workstation-demo',True,runner)
                self.assertEqual(result['status'],'applied')
                with self.assertRaises(ValueError):response.apply(p,t,self.cfg,self.key,NOW,state,'workstation-demo',True,runner)
                r=response.rollback(a['id'],self.key,state,NOW,'workstation-demo',True,runner,lambda _:True)
                self.assertEqual(r['status'],'rolled_back')
        self.assertEqual(len(calls),3)

    def test_audit_tampering_detected(self):
        j=response.Journal(self.root/'state',self.key)
        try:
            j.append({'event':'one'});j.db.commit();self.assertTrue(j.verify()['verified'])
            j.db.execute("UPDATE audit SET payload='{}'");j.db.commit()
            with self.assertRaises(ValueError):j.verify()
        finally:j.close()

    def test_key_permission_guard(self):
        k=self.root/'key';response.new_key(k);self.assertEqual(len(response.key_bytes(k)),32)
        if os.name=='posix':
            os.chmod(k,0o644)
            with self.assertRaises(ValueError):response.key_bytes(k)


class PolicyTests(Fixture):
    def test_no_implicit_trust_from_network(self):
        r=dict(self.request,identity_verified=False,src_ip='10.0.0.1')
        self.assertEqual(policy.access_decision(r,self.cfg,NOW)['decision'],'deny')

    def test_explicit_verified_access_short_lease(self):
        r=policy.access_decision(self.request,self.cfg,NOW)
        self.assertEqual((r['decision'],r['lease_seconds']),('allow',60))

    def test_stale_posture_denied(self):
        r=dict(self.request,posture_checked_at=iso(NOW-timedelta(hours=1)))
        self.assertEqual(policy.access_decision(r,self.cfg,NOW)['decision'],'deny')

    def test_mfa_step_up(self):
        self.assertEqual(policy.access_decision(dict(self.request,mfa_verified=False),self.cfg,NOW)['decision'],'step_up')

    def test_high_risk_denied(self):
        self.assertEqual(policy.access_decision(self.request,self.cfg,NOW,90)['decision'],'deny')


class DiscoveryTests(Fixture):
    def scope(self):return {'networks':['192.0.2.0/24'],'domains':['example.test']}
    def records(self):return [{'ip':'192.0.2.11','port':443,'transport':'tcp','time':iso(NOW),'service':{'name':'https'}}]

    def test_quake_network_scope_and_no_auto_enrollment(self):
        s=assets.normalize_assets(self.records()+[{'ip':'198.51.100.1','port':80}],self.scope(),NOW,self.cfg)
        self.assertEqual(len(s['assets']),1);self.assertEqual(s['out_of_scope'],1)
        self.assertEqual(s['assets'][0]['registered_host'],'web-demo');self.assertFalse(s['assets'][0]['response_enabled'])

    def test_domain_scope_suffix_boundary(self):
        rows=[{'ip':'198.51.100.1','port':80,'domain':'evil-example.test'},
              {'ip':'198.51.100.2','port':80,'domain':'app.example.test'}]
        s=assets.normalize_assets(rows,self.scope(),NOW)
        self.assertEqual(len(s['assets']),1);self.assertEqual(s['assets'][0]['ip'],'198.51.100.2')

    def test_quake_bounded_pagination(self):
        calls=[]
        def fetch(payload,token):
            calls.append(payload)
            return {'code':0,'data':[{'ip':'192.0.2.11','port':p+1+payload['start']} for p in range(payload['size'])]}
        s=assets.search('port:443',self.scope(),NOW,limit=7,page_size=3,fetcher=fetch,token='dummy')
        self.assertEqual([x['size'] for x in calls],[3,3,1]);self.assertEqual(s['records_received'],7)
        self.assertTrue(all(' AND (' in x['query'] for x in calls))

    def test_scope_escape_rejected(self):
        with self.assertRaises(ValueError):assets.scoped_query('*) OR *',self.scope())

    def test_empty_scope_rejected(self):
        with self.assertRaises(ValueError):assets.scope_config({})

    def test_quake_api_error_propagates(self):
        with self.assertRaises(ValueError):assets.search('*',self.scope(),NOW,fetcher=lambda *x:{'code':401},token='dummy')

    def test_asset_diff_observations(self):
        a=assets.normalize_assets(self.records(),self.scope(),NOW)
        b=assets.normalize_assets([],self.scope(),NOW)
        self.assertEqual(len(assets.asset_diff(a,b)['not_seen']),1)

    def test_knowledge_only_article_links(self):
        text=b'- [Response](articles/response.md)\n- [Bad](javascript:alert(1))\n- [Outside](../secret)'
        idx=knowledge.index_readme(text,'main',NOW)
        self.assertEqual(len(idx['entries']),1);self.assertFalse(idx['entries'][0]['executable'])
        self.assertEqual(len(knowledge.search(idx,'Response')),1)

    def test_knowledge_revision_injection(self):
        with self.assertRaises(ValueError):knowledge.index_readme(b'', '../main', NOW)


if __name__=='__main__':unittest.main()
