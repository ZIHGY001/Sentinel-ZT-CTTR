import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sentinel_zt import behavior_demo, demo, engine, events, intel, policy, report, runbooks
from sentinel_zt.common import now_utc, timestamp


class RunbookTests(unittest.TestCase):
    def setUp(self):
        self.now = now_utc()
        rows, self.cfg = behavior_demo.fixtures(self.now)
        self.analysis = engine.analyze([events.canonical_event(e, 'test', i) for i,e in enumerate(rows)], [], self.now, self.cfg)
        self.incident = self.analysis['incidents'][0]
        self.doc = runbooks.create(self.analysis, self.incident['id'], 'linux', self.now)

    def payload(self, **changes):
        return dict(expected_revision=0,status='needs_data',reviewer='Lab analyst',observation='Missing authentication log',evidence_ids=[],artifacts=[],**changes)

    def test_behavior_only_match_and_platform_boundary(self):
        ids = {b['id'] for b in self.doc['runbooks']}
        self.assertTrue({'IR-CORE','IR-LINUX','IR-LATERAL','IR-PRIVILEGE'} <= ids)
        self.assertNotIn('IR-WINDOWS',ids)
        unknown = runbooks.create(self.analysis,self.incident['id'],'unknown',self.now)
        self.assertNotIn('IR-LINUX',{b['id'] for b in unknown['runbooks']})
        windows = runbooks.create(self.analysis,self.incident['id'],'windows',self.now)
        self.assertNotIn('IR-LINUX',{b['id'] for b in windows['runbooks']})
        self.assertIn('IR-WINDOWS',{b['id'] for b in windows['runbooks']})

    def test_recommendations_do_not_change_detection_or_authorization(self):
        plan=engine.make_plan(self.analysis,self.cfg,self.now)
        snapshot=copy.deepcopy(self.analysis)
        runbooks.review(self.doc,'IR-001',self.payload(),self.now)
        self.assertEqual(self.analysis,snapshot)
        self.assertEqual(engine.make_plan(self.analysis,self.cfg,self.now),plan)

    def test_bad_incident_or_platform_rejected(self):
        for incident,platform in [('missing','linux'),(self.incident['id'],'auto')]:
            with self.assertRaises(ValueError):runbooks.create(self.analysis,incident,platform,self.now)

    def test_negative_and_positive_claims_require_evidence(self):
        for status in ['not_observed','suspicious']:
            payload=self.payload();payload['status']=status
            with self.assertRaises(ValueError):runbooks.review(self.doc,'IR-001',payload,self.now)
            payload['evidence_ids']=[self.doc['available_evidence'][0]['id']]
            result=runbooks.review(self.doc,'IR-001',payload,self.now)
            self.assertEqual(result['checks'][0]['status'],status)

    def test_missing_data_stays_unresolved(self):
        updated=runbooks.review(self.doc,'IR-001',self.payload(),self.now)
        self.assertEqual(runbooks.summarize(updated)['unresolved'],len(updated['checks']))
        self.assertEqual(runbooks.summarize(updated)['reviewed'],0)

    def test_cross_incident_and_duplicate_evidence_rejected(self):
        for ids in [['event-from-another-host'],[self.doc['available_evidence'][0]['id']]*2,[1]]:
            payload=self.payload();payload['evidence_ids']=ids
            with self.assertRaises(ValueError):runbooks.review(self.doc,'IR-001',payload,self.now)

    def test_external_artifact_requires_hash_and_explicit_time(self):
        payload=self.payload();payload['status']='not_observed'
        artifact={'name':'auth.log preserved copy','sha256':'a'*64,'collected_at':'2020-01-01T00:00:00Z'}
        payload['artifacts']=[artifact]
        result=runbooks.review(self.doc,'IR-001',payload,self.now)
        self.assertEqual(result['history'][0]['artifacts'][0]['verification'],'analyst_supplied_not_verified')
        for change in [{'sha256':'a'*63},{'collected_at':'2999-01-01T00:00:00Z'}, {'collected_at':'2020-01-01'}, {'collected_at':3},{'command':'rm'}, {'name':''}]:
            payload['artifacts']=[{**artifact,**change}]
            with self.assertRaises(ValueError):runbooks.review(self.doc,'IR-001',payload,self.now)

    def test_revisions_preserve_prior_observations(self):
        updated=runbooks.review(self.doc,'IR-001',self.payload(),self.now)
        payload=self.payload();payload.update(expected_revision=1,status='pending',observation='Reopened after new evidence')
        reopened=runbooks.review(updated,'IR-001',payload,self.now)
        self.assertEqual(len(reopened['history']),2)
        self.assertEqual(reopened['history'][0]['status'],'needs_data')
        self.assertEqual(updated['checks'][0]['status'],'needs_data')
        self.assertEqual(self.doc['revision'],0)

    def test_stale_review_does_not_overwrite(self):
        updated=runbooks.review(self.doc,'IR-001',self.payload(),self.now)
        with self.assertRaises(ValueError):runbooks.review(updated,'IR-001',self.payload(),self.now)

    def test_limits_and_unknown_fields(self):
        for changes in [{'expected_revision':False},{'observation':' '},{'reviewer':'a'*101},{'status':'safe'}, {'commands':[]}]:
            payload=self.payload();payload.update(changes)
            with self.assertRaises(ValueError):runbooks.review(self.doc,'IR-001',payload,self.now)
        with self.assertRaises(ValueError):runbooks.review(self.doc,'missing',self.payload(),self.now)
        full=copy.deepcopy(self.doc);full['revision']=runbooks.MAX_REVISIONS
        payload=self.payload();payload['expected_revision']=runbooks.MAX_REVISIONS
        with self.assertRaises(ValueError):runbooks.review(full,'IR-001',payload,self.now)

    def test_feedback_cannot_be_loaded_as_policy(self):
        updated=runbooks.review(self.doc,'IR-001',self.payload(),self.now)
        feedback=runbooks.feedback(updated)
        self.assertFalse(feedback['enabled']);self.assertFalse(feedback['changes_applied'])
        self.assertNotIn('behavior_exceptions',feedback)
        with self.assertRaises(ValueError):policy.validate(feedback)

    def test_catalog_copies_and_complete_sources(self):
        c=runbooks.catalog();sources={s['id'] for s in c['sources']}
        ids=[x['id'] for b in c['runbooks'] for x in b['checks']]
        self.assertEqual(len(ids),len(set(ids)))
        for b in c['runbooks']:
            for x in b['checks']:
                self.assertTrue(set(x['source_ids'])<=sources)
                self.assertEqual(x['execution'],'manual_reference_only')
        c['runbooks'].clear()
        self.assertEqual(len(runbooks.catalog()['runbooks']),7)

    def test_report_escapes_manual_observations(self):
        payload=self.payload();payload['observation']='<script>alert(1)</script>'
        doc=runbooks.review(self.doc,'IR-001',payload,self.now)
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'report.html'
            report.render(self.analysis,engine.make_plan(self.analysis,self.cfg,self.now),p,[doc])
            text=p.read_text();self.assertNotIn('<script>',text)
            self.assertIn('&lt;script&gt;',text);self.assertIn('调查手册',text)


try:
    from fastapi.testclient import TestClient
    from sentinel_zt.api import create_app, agent_context
    WEB_AVAILABLE=True
except ImportError:
    WEB_AVAILABLE=False


@unittest.skipUnless(WEB_AVAILABLE,'install requirements-test.txt')
class RunbookAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.token='runbook-api-test-token-'+'x'*32
        self.client=TestClient(create_app(self.tmp.name,self.token,testing=True))
        self.headers={'Authorization':'Bearer '+self.token}
        self.case=self.client.post('/api/demo/behavior',json={},headers=self.headers).json()
        self.path='/api/cases/'+self.case['id']+'/runbooks'
        self.incident=self.case['analysis']['incidents'][0]['id']

    def start(self):
        r=self.client.post(self.path,json={'incident_id':self.incident,'platform':'linux'},headers=self.headers)
        self.assertEqual(r.status_code,200,r.text)
        return r.json()

    def save(self, **changes):
        payload={'expected_revision':0,'status':'needs_data','reviewer':'Reviewer','observation':'Waiting for auth logs','evidence_ids':[],'artifacts':[]}
        payload.update(changes)
        return self.client.post(self.path+'/'+self.incident+'/checks/IR-001',json=payload,headers=self.headers)

    def test_all_routes_require_auth(self):
        self.assertEqual(self.client.get('/api/runbooks').status_code,401)
        self.assertEqual(self.client.get(self.path).status_code,401)
        self.assertEqual(self.client.post(self.path,json={}).status_code,401)
        self.assertEqual(self.client.post(self.path+'/'+self.incident+'/checks/IR-001',json={}).status_code,401)

    def test_persistence_and_report_include_reviews(self):
        self.start();r=self.save();self.assertEqual(r.status_code,200,r.text)
        reload=TestClient(create_app(self.tmp.name,self.token,testing=True))
        document=reload.get(self.path,headers=self.headers).json()['worksheets'][0]
        self.assertEqual(document['revision'],1)
        report=reload.get('/api/cases/'+self.case['id']+'/report',headers=self.headers)
        self.assertEqual(report.status_code,200);self.assertIn('Waiting for auth logs',report.text)
        case=reload.get('/api/cases/'+self.case['id'],headers=self.headers).json()
        self.assertEqual(case,self.case)
        self.assertNotIn('Waiting for auth logs',json.dumps(agent_context(case['analysis'],case['plan'])))

    def test_restarting_is_idempotent_and_cannot_clear_history(self):
        self.start();self.save();document=self.start();self.assertEqual(document['revision'],1)
        r=self.client.post(self.path,json={'incident_id':self.incident,'platform':'windows'},headers=self.headers)
        self.assertEqual(r.status_code,409)

    def test_conflict_and_input_validation(self):
        self.start();self.save();self.assertEqual(self.save().status_code,409)
        for changes,code in [({'expected_revision':True},422),({'expected_revision':1,'status':'safe'},422),
                             ({'expected_revision':1,'evidence_ids':['foreign']},400),
                             ({'expected_revision':1,'status':'not_observed'},400),
                             ({'expected_revision':1,'commands':['anything']},422)]:
            r=self.save(**changes);self.assertEqual(r.status_code,code,r.text)
        self.assertEqual(self.client.get(self.path,headers=self.headers).json()['worksheets'][0]['revision'],1)

    def test_cross_case_incident_and_missing_worksheet(self):
        r=self.client.post(self.path,json={'incident_id':'not-in-case','platform':'linux'},headers=self.headers)
        self.assertEqual(r.status_code,400)
        self.assertEqual(self.save().status_code,404)
        self.assertEqual(self.client.get('/api/cases/not-a-uuid/runbooks',headers=self.headers).status_code,404)

    def test_catalog_does_not_create_an_executor(self):
        self.assertEqual(len(self.client.get('/api/runbooks',headers=self.headers).json()['runbooks']),7)
        for path in ['/api/runbooks/execute',self.path+'/execute']:
            self.assertIn(self.client.post(path,json={},headers=self.headers).status_code,(404,405))

    def test_workbook_does_not_call_shell(self):
        with patch('subprocess.run',side_effect=AssertionError('unexpected execution')):
            self.start();self.assertEqual(self.save().status_code,200)


if __name__=='__main__':unittest.main()
