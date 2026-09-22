import copy
import os
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from sentinel_zt import demo, deployment, engine, events, intel, yunmai
from sentinel_zt.common import iso, load_json, now_utc, timestamp, write_json


class YunmaiTests(unittest.TestCase):
    def setUp(self):
        self.now = timestamp("2026-09-20T12:00:00Z")
        rows, ti, policy, _ = demo.fixtures(self.now)
        ev = [events.canonical_event(x, "synthetic", i+1) for i, x in enumerate(rows)]
        self.analysis = engine.analyze(ev, [intel.Indicator.parse(x) for x in ti], self.now, policy)
        self.mapping = load_json(Path(__file__).resolve().parent.parent / "examples/yunmai-mapping.json")

    def handoff(self, at=None):
        return yunmai.handoff(self.analysis, self.mapping, at or self.now)

    def test_draft_has_no_execution_or_cloud_receipt(self):
        draft = self.handoff()
        ready = [x for x in draft['items'] if x['status'] == 'ready_for_manual_review']
        self.assertEqual(len(ready), 1)
        self.assertEqual(ready[0]['proposal']['subject']['ref'], 'user-demo')
        self.assertEqual(draft['cloud_status'], 'not_submitted')
        self.assertFalse(draft['changes_applied'])
        self.assertTrue(all(not x['executable'] for x in draft['items']))
        self.assertEqual(len(draft['analysis_digest']), 64)

    def test_unknown_asset_not_inferred_from_ip(self):
        missing = [x for x in self.handoff()['items'] if x['host'] != 'workstation-demo']
        self.assertTrue(all('verified_user_application_mapping_required' in x['gates'] for x in missing))
        self.assertTrue(all('proposal' not in x for x in missing))

    def test_stale_mapping_blocks_proposal(self):
        self.mapping['bindings'][0]['verified_at'] = iso(self.now - timedelta(hours=2))
        item = next(x for x in self.handoff()['items'] if x['host'] == 'workstation-demo')
        self.assertIn('mapping_stale_or_future', item['gates'])
        self.assertNotIn('proposal', item)

    def test_future_mapping_blocks_proposal(self):
        self.mapping['bindings'][0]['verified_at'] = iso(self.now + timedelta(seconds=1))
        self.assertTrue(all(x['status'] == 'blocked' for x in self.handoff()['items']))

    def test_old_incident_with_new_mapping_still_blocked(self):
        later = self.now + timedelta(days=2)
        self.mapping['bindings'][0]['verified_at'] = iso(later)
        self.assertTrue(all('fresh_behavior_evidence_required' in x['gates'] for x in self.handoff(later)['items']))

    def test_protected_application_cannot_be_restricted(self):
        self.mapping['bindings'][0]['application_refs'].append('app-sentinel-console')
        with self.assertRaisesRegex(ValueError, 'protected'):
            self.handoff()

    def test_wildcards_and_groups_rejected(self):
        for ref in ['*', 'app-*', 'all']:
            with self.subTest(ref=ref):
                mapping = copy.deepcopy(self.mapping)
                mapping['bindings'][0]['application_refs'] = [ref]
                with self.assertRaises(ValueError): yunmai.validate(mapping)
        self.mapping['bindings'][0]['subject']['type'] = 'group'
        with self.assertRaises(ValueError): self.handoff()

    def test_ambiguous_duplicate_host_rejected(self):
        self.mapping['bindings'].append(copy.deepcopy(self.mapping['bindings'][0]))
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            self.handoff()

    def test_ioc_only_even_high_risk_is_not_enough(self):
        incident = next(x for x in self.analysis['incidents'] if x['host'] == 'workstation-demo')
        incident['rule_ids'] = ['I001']
        self.analysis['findings'] = [f for f in self.analysis['findings'] if f['rule_id'] == 'I001']
        item = next(x for x in self.handoff()['items'] if x['host'] == 'workstation-demo')
        self.assertIn('behavior_evidence_required', item['gates'])
        self.assertNotIn('proposal', item)

    def test_extra_mapping_secrets_not_exported(self):
        self.mapping['bindings'][0]['subject']['token'] = 'not-a-real-secret'
        draft = self.handoff()
        self.assertNotIn('not-a-real-secret', str(draft))

    def test_bad_expiry_budget_rejected(self):
        self.mapping['restriction_ttl_seconds'] = 86400
        with self.assertRaises(ValueError): self.handoff()


class DeploymentTests(unittest.TestCase):
    def test_local_default(self):
        s = deployment.settings({})
        self.assertEqual(s['mode'], 'local')
        self.assertNotIn('*', s['hosts'])

    def test_https_origin_is_exact(self):
        s = deployment.settings({'SENTINEL_DEPLOYMENT_MODE':'yunmai',
                                 'SENTINEL_PUBLIC_ORIGIN':'https://IR.EXAMPLE.TEST:443/'})
        self.assertEqual(s['hosts'], ['ir.example.test'])
        self.assertEqual(s['origins'], {'https://ir.example.test'})

    def test_invalid_public_origins_fail_closed(self):
        for value in ['', 'http://ir.example.test', 'https://*.example.test',
                      'https://user:pass@ir.example.test', 'https://ir.example.test/path',
                      'https://ir.example.test?x=1', 'https://ir.example.test/#frag',
                      'https://ir.example.test:99999', 'https://ir.example.test\n']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                deployment.settings({'SENTINEL_DEPLOYMENT_MODE':'yunmai','SENTINEL_PUBLIC_ORIGIN':value})

    def test_cloud_mode_ignores_loose_local_origin_setting(self):
        s = deployment.settings({'SENTINEL_DEPLOYMENT_MODE':'yunmai','SENTINEL_PUBLIC_ORIGIN':'https://ir.example.test',
                                 'SENTINEL_ALLOWED_ORIGINS':'*', 'SENTINEL_ALLOWED_HOSTS':'*'})
        self.assertEqual(s['origins'], {'https://ir.example.test'})
        self.assertEqual(s['hosts'], ['ir.example.test'])


try:
    from fastapi.testclient import TestClient
    from sentinel_zt.api import create_app
    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False


@unittest.skipUnless(WEB_AVAILABLE, 'install requirements-test.txt to run API tests')
class YunmaiAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.mapping = Path(self.tmp.name)/'mapping.json'
        cfg = load_json(Path(__file__).resolve().parent.parent/'examples/yunmai-mapping.json')
        cfg['bindings'][0]['verified_at'] = iso(now_utc())
        write_json(self.mapping, cfg)
        env = patch.dict(os.environ, {'SENTINEL_DEPLOYMENT_MODE':'yunmai',
                                     'SENTINEL_PUBLIC_ORIGIN':'https://ir.example.test',
                                     'SENTINEL_YUNMAI_MAPPING':str(self.mapping)})
        env.start(); self.addCleanup(env.stop)
        self.token = 'synthetic-api-token-' + 'x'*40
        self.headers = {'Authorization':'Bearer '+self.token,'Origin':'https://ir.example.test'}
        self.client = TestClient(create_app(self.tmp.name,self.token),base_url='https://ir.example.test')

    def test_published_host_origin_and_existing_auth(self):
        r = self.client.get('/api/status',headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.get('/api/status').status_code, 401)

    def test_forged_sase_headers_cannot_authenticate(self):
        r = self.client.get('/api/status',headers={'X-SASE-User':'admin','X-SASE-Device':'compliant',
                                                  'X-Forwarded-For':'127.0.0.1'})
        self.assertEqual(r.status_code,401)

    def test_bad_host_and_origin_rejected(self):
        self.assertEqual(self.client.get('/api/status',headers={**self.headers,'Host':'attacker.example'}).status_code,400)
        self.assertEqual(self.client.get('/api/status',headers={**self.headers,'Origin':'https://attacker.example'}).status_code,403)

    def test_status_does_not_claim_cloud_validation(self):
        s = self.client.get('/api/integrations/yunmai',headers=self.headers).json()
        self.assertTrue(s['mapping_configured'])
        self.assertFalse(s['cloud_connection_verified'])
        self.assertFalse(s['automatic_response'])

    def test_handoff_persisted_without_cloud_calls(self):
        case = self.client.post('/api/demo',headers=self.headers,json={}).json()
        with patch('urllib.request.OpenerDirector.open',side_effect=AssertionError('unexpected network')):
            r = self.client.post('/api/cases/'+case['id']+'/yunmai-handoff',headers=self.headers,json={})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['cloud_status'],'not_submitted')
        self.assertTrue((Path(self.tmp.name)/'handoffs'/(r.json()['id']+'.json')).exists())

    def test_missing_mapping_blocks_generation(self):
        case = self.client.post('/api/demo',headers=self.headers,json={}).json()
        with patch.dict(os.environ, {'SENTINEL_YUNMAI_MAPPING':''}):
            r = self.client.post('/api/cases/'+case['id']+'/yunmai-handoff',headers=self.headers,json={})
        self.assertEqual(r.status_code,409)


if __name__ == '__main__':
    unittest.main()
