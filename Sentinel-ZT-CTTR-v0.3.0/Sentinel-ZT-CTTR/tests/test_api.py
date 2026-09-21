import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient
    from sentinel_zt.api import create_app, agent_context
    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False


@unittest.skipUnless(WEB_AVAILABLE, 'install requirements-test.txt to run API tests')
class APITests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.token='test-token-not-a-secret-'+'x'*32
        self.client=TestClient(create_app(self.tmp.name,self.token,testing=True))
        self.headers={'Authorization':'Bearer '+self.token}

    def demo(self):
        r=self.client.post('/api/demo',json={},headers=self.headers)
        self.assertEqual(r.status_code,200,r.text)
        return r.json()

    def test_token_required(self):
        self.assertEqual(self.client.get('/api/cases').status_code,401)

    def test_health_no_auth(self):
        self.assertEqual(self.client.get('/api/health').json()['status'],'ok')

    def test_demo_persisted_and_report(self):
        c=self.demo();self.assertEqual(len(c['analysis']['incidents']),3)
        r=self.client.get('/api/cases/'+c['id'],headers=self.headers)
        self.assertEqual(r.json()['plan'],c['plan'])
        r=self.client.get('/api/cases/'+c['id']+'/report',headers=self.headers)
        self.assertEqual(r.status_code,200);self.assertIn('Sentinel-ZT-CTTR',r.text)

    def test_bad_origin_denied(self):
        r=self.client.post('/api/demo',json={},headers={**self.headers,'Origin':'https://evil.example'})
        self.assertEqual(r.status_code,403)

    def test_bad_host_denied(self):
        r=self.client.get('/api/health',headers={'Host':'attacker.example'})
        self.assertEqual(r.status_code,400)

    def test_malformed_log_error(self):
        r=self.client.post('/api/analyze',json={'events_text':'{invalid'},headers=self.headers)
        self.assertEqual(r.status_code,400)

    def test_api_analysis_accepts_valid_logs(self):
        c=self.demo();e=c['analysis']['events'][0]
        r=self.client.post('/api/analyze',json={'events_text':json.dumps(e)},headers=self.headers)
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['analysis']['statistics']['analyzed_events'],1)

    def test_agent_requires_consent(self):
        c=self.demo()
        r=self.client.post('/api/agent',json={'case_id':c['id'],'question':'analyze'},headers=self.headers)
        self.assertEqual(r.status_code,400)

    def test_disabled_agent_explicit(self):
        c=self.demo()
        with patch.dict('os.environ',{'SENTINEL_PI_ENABLED':'0'}):
            r=self.client.post('/api/agent',json={'case_id':c['id'],'question':'analyze','consent_to_model':True},headers=self.headers)
        self.assertEqual(r.status_code,409)

    def test_agent_context_excludes_identifiers(self):
        c=self.demo();s=json.dumps(agent_context(c['analysis'],c['plan']))
        self.assertNotIn('203.0.113.50',s);self.assertNotIn('workstation-demo',s)
        self.assertNotIn('demo-user',s);self.assertNotIn('command_line',s)

    def test_agent_child_receives_only_selected_model_credentials(self):
        c=self.demo()
        env={'SENTINEL_PI_ENABLED':'1','PI_PROVIDER':'openai','OPENAI_API_KEY':'fake-openai',
             'ANTHROPIC_API_KEY':'fake-anthropic','QUAKE_API_KEY':'fake-quake',
             'SENTINEL_API_TOKEN':'fake-web','RESPONSE_SIGNING_KEY':'fake-response',
             'NODE_OPTIONS':'--require=unwanted-file.js'}
        result=subprocess.CompletedProcess([],0,stdout='{"text":"mock advice"}',stderr='')
        with patch.dict('os.environ',env), patch('sentinel_zt.api.subprocess.run',return_value=result) as run:
            r=self.client.post('/api/agent',json={'case_id':c['id'],'question':'analyze','consent_to_model':True},headers=self.headers)
        self.assertEqual(r.status_code,200,r.text)
        child=run.call_args.kwargs['env']
        self.assertEqual(child['OPENAI_API_KEY'],'fake-openai')
        self.assertFalse({'ANTHROPIC_API_KEY','QUAKE_API_KEY','SENTINEL_API_TOKEN',
                          'RESPONSE_SIGNING_KEY','NODE_OPTIONS'} & child.keys())

    def test_no_live_apply_endpoint(self):
        r=self.client.post('/api/apply',json={},headers=self.headers)
        self.assertIn(r.status_code,(404,405))

    def test_offline_quake_import(self):
        body={'records':[{'ip':'192.0.2.10','port':443}],'scope':{'networks':['192.0.2.0/24']}}
        r=self.client.post('/api/assets/import',json=body,headers=self.headers)
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(len(self.client.get('/api/assets',headers=self.headers).json()['assets']),1)

    def test_knowledge_index_search(self):
        r=self.client.post('/api/knowledge/index',json={'readme':'- [应急响应分析](articles/response.md)'},headers=self.headers)
        self.assertEqual(r.json()['indexed'],1)
        r=self.client.get('/api/knowledge/search?q=应急响应',headers=self.headers)
        self.assertEqual(len(r.json()['results']),1)

    def test_short_token_rejected(self):
        with self.assertRaises(ValueError):create_app(self.tmp.name,'short',testing=True)


if __name__=='__main__':unittest.main()
