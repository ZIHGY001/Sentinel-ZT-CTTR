"""Behavior-first analytics, reviewed exceptions, coverage and no-IOC response."""
import copy
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from sentinel_zt import baselines, behavior_demo, engine, events, intel, policy, response, yunmai
from sentinel_zt.common import digest, iso, load_json, now_utc, timestamp

NOW = timestamp('2026-09-21T12:00:00Z')


class BaselineFixture(unittest.TestCase):
    def setUp(self):
        self.rows, self.cfg = behavior_demo.fixtures(NOW)
        self.profile = self.cfg['behavior_baselines']['workstation']

    def analyze(self, rows=None, indicators=(), cfg=None):
        cfg = self.cfg if cfg is None else cfg
        policy.validate(cfg)
        ev = [events.canonical_event(x, 'synthetic', i+1) for i,x in enumerate(self.rows if rows is None else rows)]
        ev = list({e['id']:e for e in ev}.values())
        return engine.analyze(ev, list(indicators), NOW, cfg)

    def remote(self):
        return [x for x in self.rows if x['event_type']=='network' and x['host']=='workstation-demo' and x['dst_ip']!='192.0.2.30']

    def coverage(self, analysis, host='workstation-demo'):
        return next(x for x in analysis['behavior_baseline']['assets'] if x['host']==host)

    def exception(self):
        row = self.remote()[0]
        item = {'id':'change-demo','host':'workstation-demo','rule_id':'B101',
                'match':{k:row[k] for k in baselines.EXCEPTION_FIELDS['B101']},
                'valid_from':iso(NOW-timedelta(hours=1)),'valid_until':iso(NOW+timedelta(hours=1)),
                'reason':'reviewed synthetic maintenance','reviewed_by':'lab-reviewer'}
        self.cfg['behavior_exceptions']=[item]
        return item


class BaselineDetectionTests(BaselineFixture):
    def test_no_ioc_exercise_detects_behavior_chain(self):
        a=self.analyze()
        self.assertEqual({f['rule_id'] for f in a['findings']},{'B101','B102','B103','B104','C101'})
        self.assertEqual(len(a['findings']),7)
        self.assertEqual(len(a['incidents']),1)
        self.assertGreaterEqual(a['incidents'][0]['risk'],70)
        self.assertEqual(a['incidents'][0]['scoring']['intel_corroboration'],0)
        self.assertTrue(all(not f['intel'] for f in a['findings']))

    def test_role_context_keeps_expected_bastion_and_workflows_quiet(self):
        a=self.analyze()
        self.assertEqual(self.coverage(a,'bastion-demo')['expected_events'],3)
        self.assertEqual(self.coverage(a)['expected_events'],3)
        self.assertFalse(any(f['host']=='bastion-demo' for f in a['findings']))

    def test_no_ioc_case_can_generate_manual_yunmai_handoff(self):
        a=self.analyze(); p=engine.make_plan(a,self.cfg,NOW)
        self.assertFalse(any(x['executable'] for x in p['actions']))
        mapping=load_json(Path(__file__).resolve().parent.parent/'examples/yunmai-mapping.json')
        mapping['bindings'][0]['verified_at']=iso(NOW)
        result=yunmai.handoff(a,mapping,NOW)
        self.assertEqual(result['items'][0]['status'],'ready_for_manual_review')
        self.assertFalse(result['changes_applied'])

    def test_chain_requires_exact_account(self):
        for row in self.rows:
            if row['event_type']=='network': row['user']='different-user'
        self.assertNotIn('C101',{f['rule_id'] for f in self.analyze()['findings']})

    def test_chain_requires_order_and_window(self):
        for ago in (10,2000):
            rows=copy.deepcopy(self.rows)
            for row in rows:
                if row['event_type'] in {'identity','privilege'}:row['timestamp']=iso(NOW-timedelta(seconds=ago))
            with self.subTest(ago=ago):
                self.assertNotIn('C101',{f['rule_id'] for f in self.analyze(rows)['findings']})

    def test_fanout_counts_distinct_targets(self):
        rows=self.remote()
        for row in rows:row['dst_ip']='192.0.2.20'
        self.assertNotIn('B102',{f['rule_id'] for f in self.analyze(rows)['findings']})

    def test_fanout_uses_a_sliding_time_window(self):
        rows=self.remote()
        for i,row in enumerate(rows):row['timestamp']=iso(NOW-timedelta(seconds=100+400*i))
        self.assertNotIn('B102',{f['rule_id'] for f in self.analyze(rows)['findings']})

    def test_wrong_source_asset_is_a_coverage_gap(self):
        rows=self.remote()
        for row in rows:row['src_ip']='192.0.2.99'
        a=self.analyze(rows)
        self.assertEqual(a['findings'],[])
        self.assertIn('network_source_not_registered_asset',self.coverage(a)['gaps'])

    def test_unknown_protocol_is_not_assumed_tcp(self):
        rows=self.remote()
        for row in rows:row.pop('transport')
        a=self.analyze(rows)
        self.assertEqual(a['findings'],[])
        self.assertIn('network_fields_missing',self.coverage(a)['gaps'])

    def test_missing_or_failed_identity_outcome_is_not_success(self):
        row=next(x for x in self.rows if x['event_type']=='identity')
        for outcome in (None,'unknown','failure'):
            modified={**row,'outcome':outcome};a=self.analyze([modified])
            self.assertNotIn('B103',{f['rule_id'] for f in a['findings']})
            if outcome!='failure': self.assertIn('identity_change_fields_missing',self.coverage(a)['gaps'])

    def test_allowed_change_does_not_cover_another_actor_or_role(self):
        row=next(x for x in self.rows if x.get('actor')=='iam-service')
        for field,value in [('actor','intruder'),('target_role','DomainAdmin'),('target_user','other-user')]:
            with self.subTest(field=field):
                self.assertIn('B103',{f['rule_id'] for f in self.analyze([{**row,field:value}])['findings']})

    def test_explicit_denial_cannot_be_hidden_by_an_expected_path(self):
        row=next(x for x in self.rows if x.get('actor')=='iam-service')
        self.assertIn('B103',{f['rule_id'] for f in self.analyze([{**row,'authorized':False}])['findings']})

    def test_criticality_changes_priority_but_not_execution_authority(self):
        a=self.analyze();before=a['incidents'][0]['risk']
        self.cfg['assets']['workstation-demo']['criticality']='critical'
        a=self.analyze()
        self.assertEqual(a['incidents'][0]['risk'],min(99,before+8))
        self.assertEqual(a['incidents'][0]['scoring']['asset_priority'],8)
        self.assertFalse(any(x['executable'] for x in engine.make_plan(a,self.cfg,NOW)['actions']))

    def test_missing_and_expired_baselines_report_gaps(self):
        for state in ('draft','expired','not_yet_valid','unconfigured'):
            cfg=copy.deepcopy(self.cfg);p=cfg['behavior_baselines']['workstation']
            if state=='draft':p['enabled']=False
            elif state=='expired':p['valid_until']=iso(NOW)
            elif state=='not_yet_valid':p['valid_from']=iso(NOW+timedelta(seconds=1))
            else:cfg['assets']['workstation-demo'].pop('baseline_profile')
            a=self.analyze(cfg=cfg)
            self.assertEqual(self.coverage(a)['status'],state)
            self.assertFalse(any(f.get('baseline') and f['host']=='workstation-demo' for f in a['findings']))

    def test_unobserved_asset_is_visible_as_missing_telemetry(self):
        a=self.analyze([]);coverage=self.coverage(a)
        self.assertEqual(coverage['status'],'active')
        self.assertIn('no_evaluable_behavior_events',coverage['gaps'])

    def test_events_before_baseline_approval_window_are_not_compared(self):
        self.profile['valid_from']=iso(NOW-timedelta(seconds=1))
        a=self.analyze()
        self.assertIn('event_outside_baseline_validity',self.coverage(a)['gaps'])
        self.assertFalse(any(f['host']=='workstation-demo' for f in a['findings']))

    def test_exact_time_bounded_exception_is_auditable(self):
        self.exception();a=self.analyze()
        self.assertEqual(self.coverage(a)['exception_events'],1)
        self.assertEqual(len(a['behavior_baseline']['exceptions_applied']),1)
        self.assertEqual(sum(f['rule_id']=='B101' for f in a['findings']),2)
        self.assertNotIn('B102',{f['rule_id'] for f in a['findings']})

    def test_expired_exception_does_not_suppress(self):
        self.exception()['valid_until']=iso(NOW)
        a=self.analyze()
        self.assertEqual(self.coverage(a)['exception_events'],0)
        self.assertIn('B102',{f['rule_id'] for f in a['findings']})

    def test_event_claims_cannot_create_an_exception(self):
        for row in self.rows:row.update(baseline_exception=True,approved=True)
        self.assertEqual(sum(f['rule_id']=='B101' for f in self.analyze()['findings']),3)

    def test_exception_does_not_hide_ioc_or_explicit_denial(self):
        item=self.exception();row=self.remote()[0]
        indicator=intel.Indicator.parse({'type':'ip','value':row['dst_ip'],'source':'synthetic','confidence':90,
            'valid_from':iso(NOW-timedelta(days=1)),'valid_until':iso(NOW+timedelta(days=1))})
        a=self.analyze(indicators=[indicator]);self.assertIn('I001',{f['rule_id'] for f in a['findings']})
        a=self.analyze([{**row,'authorized':False}])
        self.assertIn('B101',{f['rule_id'] for f in a['findings']})
        self.assertEqual(a['behavior_baseline']['exceptions_applied'],[])

    def test_baseline_expiry_caps_approval_and_handoff(self):
        self.profile['valid_until']=iso(NOW+timedelta(seconds=3))
        self.cfg['operators']=['lab'];self.cfg['assets']['workstation-demo']['response_enabled']=True
        row=self.remote()[0]
        indicator=intel.Indicator.parse({'type':'ip','value':row['dst_ip'],'source':'synthetic','confidence':90,
            'valid_from':iso(NOW-timedelta(days=1)),'valid_until':iso(NOW+timedelta(days=1))})
        a=self.analyze(indicators=[indicator]);p=engine.make_plan(a,self.cfg,NOW)
        action=next(x for x in p['actions'] if x['type']=='block_peer')
        token=response.approve(p,action['id'],self.cfg,'lab',b'x'*32,NOW)
        self.assertEqual(token['payload']['expires_at'],self.profile['valid_until'])
        with self.assertRaisesRegex(ValueError,'baseline'):
            response.validate_action(p,action,self.cfg,NOW+timedelta(seconds=4))
        mapping=load_json(Path(__file__).resolve().parent.parent/'examples/yunmai-mapping.json')
        mapping['bindings'][0]['verified_at']=iso(NOW)
        self.assertEqual(yunmai.handoff(a,mapping,NOW)['review_before'],self.profile['valid_until'])
        self.assertEqual(engine.fresh_behaviors(a,NOW+timedelta(seconds=4),900),{})

    def test_access_cannot_use_an_expired_baseline_or_unevaluable_logs(self):
        request={'subject':'analyst','resource':'workstation-demo','action':'read','identity_verified':True,
                 'mfa_verified':True,'device_managed':True,'device_compliant':True,'token_valid':True,'posture_checked_at':iso(NOW)}
        self.cfg['assets']['workstation-demo']['permissions']={'analyst':['read']}
        row={'timestamp':iso(NOW),'host':'workstation-demo','event_type':'process_snapshot'}
        a=self.analyze([row])
        with self.assertRaisesRegex(ValueError,'evaluable'):
            policy.access_from_analysis(request,self.cfg,a,NOW)
        self.profile['valid_until']=iso(NOW);a=self.analyze(self.remote())
        with self.assertRaisesRegex(ValueError,'active reviewed baseline'):
            policy.access_from_analysis(request,self.cfg,a,NOW)


class BaselineValidationTests(BaselineFixture):
    def test_baseline_models_cannot_use_broad_legacy_suppression(self):
        for model in baselines.catalog():
            self.cfg['suppressions']=[{'rule_id':model['id'],'host':'workstation-demo','reason':'too broad',
                                      'expires_at':iso(NOW+timedelta(hours=1))}]
            with self.subTest(rule=model['id']),self.assertRaisesRegex(ValueError,'exact behavior_exceptions'):
                policy.validate(self.cfg)

    def test_template_is_valid_but_disabled(self):
        cfg=baselines.template(NOW);policy.validate(cfg)
        self.assertTrue(all(not p['enabled'] for p in cfg['behavior_baselines'].values()))
        self.assertTrue(all(not a['response_enabled'] for a in cfg['assets'].values()))

    def test_profile_typos_and_bad_numeric_types_are_refused(self):
        for field,value in [('fanout_threshold',True),('fanout_threshold',1),('fanout_window_seconds',0),
                            ('remote_ports',[True]),('internal_networks',['192.0.2.10/24']),('allowd_flows',[])]:
            cfg=copy.deepcopy(self.cfg);cfg['behavior_baselines']['workstation']['network'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):policy.validate(cfg)

    def test_unknown_or_mismatched_role_binding_is_refused(self):
        for field,value in [('baseline_profile','missing'),('baseline_profile',[]),('role','bastion')]:
            cfg=copy.deepcopy(self.cfg);cfg['assets']['workstation-demo'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):policy.validate(cfg)

    def test_wildcard_or_broad_exception_is_refused(self):
        item=self.exception()
        for field,value in [('src_ip','*'),('dst_port',True),('extra','x')]:
            cfg=copy.deepcopy(self.cfg);cfg['behavior_exceptions'][0]['match'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):policy.validate(cfg)
        item['valid_until']=iso(NOW+timedelta(days=2))
        with self.assertRaises(ValueError):policy.validate(self.cfg)

    def test_new_identity_fields_are_strict_strings(self):
        for field in ('user','actor','target_user','target_role','transport','outcome'):
            with self.subTest(field=field),self.assertRaises(ValueError):
                events.canonical_event({**self.rows[0],field:['untrusted']},'test',1)


try:
    from fastapi.testclient import TestClient
    from sentinel_zt.api import create_app, agent_context
    WEB_AVAILABLE=True
except ImportError:
    WEB_AVAILABLE=False


@unittest.skipUnless(WEB_AVAILABLE,'install requirements-test.txt')
class BaselineAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.client=TestClient(create_app(self.tmp.name,'t'*32,testing=True),raise_server_exceptions=False)
        self.addCleanup(self.client.close);self.headers={'Authorization':'Bearer '+'t'*32}

    def test_baseline_routes_require_authentication(self):
        for path in ('/api/behavior/models','/api/baselines/template'):
            self.assertEqual(self.client.get(path).status_code,401)
        self.assertEqual(self.client.post('/api/demo/behavior',json={}).status_code,401)

    def test_template_can_be_checked_without_activating_anything(self):
        cfg=self.client.get('/api/baselines/template',headers=self.headers).json()
        result=self.client.post('/api/baselines/validate',json={'policy_config':cfg},headers=self.headers)
        self.assertEqual(result.status_code,200,result.text)
        self.assertEqual(result.json()['profiles'][0]['status'],'draft')
        self.assertFalse(result.json()['changes_applied'])
        self.assertEqual(self.client.get('/api/cases',headers=self.headers).json(),[])

    def test_no_ioc_api_demo_persists_and_exports_evidence(self):
        result=self.client.post('/api/demo/behavior',json={},headers=self.headers)
        self.assertEqual(result.status_code,200,result.text);c=result.json()
        self.assertEqual(len(c['analysis']['incidents']),1)
        self.assertTrue(all(not f['intel'] for f in c['analysis']['findings']))
        report=self.client.get('/api/cases/'+c['id']+'/report',headers=self.headers)
        self.assertEqual(report.status_code,200)
        self.assertIn('行为基线偏离',report.text)
        self.assertIn('基线覆盖',report.text)

    def test_baseline_context_does_not_leak_raw_identities_to_pi(self):
        c=self.client.post('/api/demo/behavior',json={},headers=self.headers).json()
        payload=json.dumps(agent_context(c['analysis'],c['plan']))
        for raw in ('192.0.2.','alice-demo','helpdesk-demo','DomainAdmin','workstation-demo','bastion-demo'):
            self.assertNotIn(raw,payload)

    def test_bad_profile_structure_returns_400_not_500(self):
        _,cfg=behavior_demo.fixtures(now_utc())
        for value in (None,[],True,{'enabled':True}):
            body=copy.deepcopy(cfg);body['behavior_baselines']['workstation']=value
            result=self.client.post('/api/baselines/validate',json={'policy_config':body},headers=self.headers)
            self.assertEqual(result.status_code,400,result.text)


if __name__=='__main__':unittest.main()
