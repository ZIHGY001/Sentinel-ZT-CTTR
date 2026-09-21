"""Synthetic regressions for the v0.2.1 secure-coding review; no live response."""
import copy
import hashlib
import json
import os
import socket
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from sentinel_zt import demo, engine, events, intel, knowledge, policy, report, response, yunmai
from sentinel_zt.common import iso, load_json, now_utc, private_directory, private_file, strict_json, timestamp
from sentinel_zt.rules import detect, get_rules

NOW = timestamp('2026-09-21T12:00:00Z')


class SecurityCoreTests(unittest.TestCase):
    def setUp(self):
        self.rows, ti, self.cfg, self.request = demo.fixtures(NOW)
        self.ev = [events.canonical_event(r, 'synthetic', i + 1) for i, r in enumerate(self.rows)]
        self.iocs = [intel.Indicator.parse(r) for r in ti]
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_permission_strings_cannot_authorize_substrings(self):
        self.cfg['assets'][self.request['resource']]['permissions'][self.request['subject']] = 'read_sensitive'
        with self.assertRaisesRegex(ValueError, 'permissions'):
            policy.access_decision(self.request, self.cfg, NOW)

    def test_exact_permission_list_does_not_authorize_prefix(self):
        self.cfg['assets'][self.request['resource']]['permissions'][self.request['subject']] = ['read_sensitive']
        self.assertEqual(policy.access_decision(self.request, self.cfg, NOW)['decision'], 'deny')

    def test_risk_must_be_bounded_integer(self):
        for risk in (float('nan'), float('inf'), -1, 100, True, '0', None):
            with self.subTest(risk=risk), self.assertRaises(ValueError):
                policy.access_decision(self.request, self.cfg, NOW, risk)

    def test_empty_action_rejected(self):
        with self.assertRaises(ValueError):
            policy.access_decision({**self.request, 'action': ''}, self.cfg, NOW)

    def test_numeric_policy_strings_rejected_before_analysis(self):
        for field in ('analysis_window_seconds', 'response_threshold', 'block_ttl_seconds'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                policy.validate({**self.cfg, field: str(self.cfg[field])})

    def test_unknown_criticality_is_not_treated_as_normal(self):
        self.cfg['assets']['web-demo']['criticality'] = 'CRITICAL'
        with self.assertRaises(ValueError):
            policy.validate(self.cfg)

    def test_yunmai_string_ttl_rejected(self):
        mapping = load_json(Path(__file__).resolve().parent.parent / 'examples/yunmai-mapping.json')
        mapping['review_ttl_seconds'] = '600'
        with self.assertRaises(ValueError):
            yunmai.validate(mapping)

    def test_derived_fields_do_not_create_fake_process_evidence(self):
        row = {'timestamp': iso(NOW), 'host': 'synthetic', 'event_type': 'process_start',
               'process_name': 'cmd.exe', 'parent_process_name': 'winword.exe'}
        event = events.canonical_event(row, 'test', 1)
        self.assertNotIn('B001', {x['id'] for x in detect(event, get_rules())})

    def test_derived_fields_are_recomputed_from_raw_processes(self):
        row = {**self.rows[0], 'process_name': 'innocent.exe', 'parent_process_name': 'innocent.exe'}
        event = events.canonical_event(row, 'test', 1)
        self.assertIn('B001', {x['id'] for x in detect(event, get_rules())})

    def test_conflicting_query_cannot_hide_request_indicators(self):
        row = {'timestamp': iso(NOW), 'host': 'h', 'event_type': 'http',
               'path': '/download?file=../../secret', 'query': ''}
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            events.canonical_event(row, 'test', 1)

    def test_double_slash_request_preserves_download_path(self):
        row = {'timestamp': iso(NOW), 'host': 'h', 'event_type': 'http',
               'path': '//download?file=../../secret'}
        event = events.canonical_event(row, 'test', 1)
        self.assertIn('B009', {r['id'] for r in detect(event, get_rules())})

    def test_adapter_provenance_hashes_imported_line(self):
        row = {'Event': {'System': {'EventID': 1, 'Computer': 'h'},
                         'EventData': {'UtcTime': iso(NOW), 'Image': 'cmd.exe'},
                         'ExtraEvidence': 'retained-by-source-hash'}}
        line = json.dumps(row, separators=(', ', ': '))
        path = self.root / 'sysmon.jsonl'
        path.write_text(line + '\n')
        result, _, _ = events.load_events([path], 'sysmon')
        self.assertEqual(result[0]['evidence']['raw_sha256'], hashlib.sha256(line.encode()).hexdigest())

    def test_ambiguous_json_rejected(self):
        for raw in ('{"a":1,"a":2}', '{"risk":NaN}', '{"risk":1e999}',
                    '{"text":"\\ud800"}', '[' * 1000 + '0' + ']' * 1000):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                strict_json(raw)

    def test_duplicate_event_fields_rejected(self):
        path = self.root / 'duplicate.jsonl'
        path.write_text('{"timestamp":"' + iso(NOW) + '","host":"first","host":"second","event_type":"http"}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            events.load_events([path])

    def test_scoped_address_never_enters_firewall_script(self):
        action = {'id': 'action-' + 'a' * 20, 'peer_ip': '2001:db8::1%lo', 'ttl_seconds': 300}
        with self.assertRaises(ValueError):
            response.render_nft(action)

    def test_numeric_ip_is_not_silently_coerced(self):
        with self.assertRaises(ValueError):
            events.canonical_event({**self.rows[0], 'src_ip': 1234}, 'test', 1)

    def test_ipv4_mapped_ipv6_cannot_bypass_protected_peers(self):
        self.assertTrue(engine.protected_ip('::ffff:192.0.2.254', self.cfg))

    def test_ioc_fanout_rejected(self):
        indicators = [intel.Indicator.parse({**self.iocs[0].__dict__, 'id': str(i)}) for i in range(101)]
        with self.assertRaisesRegex(ValueError, 'fan-out'):
            intel.IntelIndex(indicators, NOW)

    def test_ioc_expansion_budget_aborts_instead_of_partial_success(self):
        index = intel.IntelIndex(self.iocs, NOW)
        with patch('sentinel_zt.intel.MAX_HIT_BYTES', 1), self.assertRaisesRegex(ValueError, 'expansion'):
            index.match(self.ev[3])

    def test_event_budget_is_enforced(self):
        with self.assertRaisesRegex(ValueError, 'event limit'):
            engine.analyze([self.ev[0]] * 10001, self.iocs, NOW, self.cfg)

    def test_report_expansion_is_rejected_without_partial_file(self):
        analysis = engine.analyze(self.ev, self.iocs, NOW, self.cfg)
        plan = engine.make_plan(analysis, self.cfg, NOW)
        target = self.root / 'report.html'
        with patch('sentinel_zt.report.MAX_REPORT_BYTES', 1), self.assertRaisesRegex(ValueError, 'report exceeds'):
            report.render(analysis, plan, target)
        self.assertFalse(target.exists())

    def test_malformed_markdown_does_not_block_valid_next_entry(self):
        raw = ('- [' + '](' * 100000 + '\n- [Response](articles/response.md)').encode()
        result = knowledge.index_readme(raw, 'main', NOW)
        self.assertEqual([x['title'] for x in result['entries']], ['Response'])

    def test_fractional_timestamp_order_is_chronological(self):
        a = copy.deepcopy(self.ev[0]); b = copy.deepcopy(a)
        a['timestamp'] = '2026-09-21T11:59:00Z'
        b.update(id='evt-later', timestamp='2026-09-21T11:59:00.500000Z')
        result = engine.analyze([a, b], [], NOW, self.cfg)
        self.assertEqual(result['incidents'][0]['last_seen'], b['timestamp'])

    @unittest.skipUnless(os.name == 'posix', 'POSIX permissions')
    def test_existing_world_readable_data_directory_rejected(self):
        path = self.root / 'public'; path.mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError, '0700'):
            private_directory(path)

    @unittest.skipUnless(os.name == 'posix', 'POSIX filesystem links')
    def test_private_files_reject_symlinks_and_hardlinks(self):
        target = self.root / 'target'; private_file(target)
        link = self.root / 'link'; link.symlink_to(target)
        with self.assertRaises((OSError, ValueError)):
            private_file(link)
        link.unlink(); os.link(target, link)
        with self.assertRaises(ValueError):
            private_file(link)

    @unittest.skipUnless(os.name == 'posix', 'POSIX locking')
    def test_journal_busy_fails_without_waiting_on_stale_authorization(self):
        first = response.Journal(self.root / 'state', b'x' * 32)
        try:
            with self.assertRaisesRegex(ValueError, 'busy'):
                response.Journal(self.root / 'state', b'x' * 32)
        finally:
            first.close()

    def test_approval_expiring_during_preflight_never_executes(self):
        self.cfg['assets']['workstation-demo']['local_hostname'] = socket.gethostname()
        analysis = engine.analyze(self.ev, self.iocs, NOW, self.cfg)
        plan = engine.make_plan(analysis, self.cfg, NOW)
        action = next(a for a in plan['actions'] if a['type'] == 'block_peer'
                      and a['host'] == 'workstation-demo' and a['executable'])
        key = b'x' * 32
        approval = response.approve(plan, action['id'], self.cfg, 'lab-analyst', key, NOW, lifetime=1)
        calls = []
        def runner(script, check=False):
            calls.append(check)
        with patch('sentinel_zt.response.require_root'), self.assertRaises(RuntimeError):
            response.apply(plan, approval, self.cfg, key, NOW, self.root / 'state', action['host'],
                           live=True, runner=runner, clock=iter([NOW, NOW + timedelta(seconds=2)]).__next__)
        self.assertEqual(calls, [True])


try:
    from fastapi.testclient import TestClient
    from sentinel_zt.api import create_app
    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False


@unittest.skipUnless(WEB_AVAILABLE, 'install requirements-test.txt')
class SecurityAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.app = create_app(self.tmp.name, 't' * 32, testing=True)
        self.client = TestClient(self.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.headers = {'Authorization': 'Bearer ' + 't' * 32}
        self.rows, self.ti, self.cfg, _ = demo.fixtures(now_utc())

    def test_malformed_iocs_and_policy_never_return_500(self):
        values = (None, [], {}, True, 1, 0, 'bad', '', ['x'])
        for value in values:
            for field in ('type', 'value', 'source', 'valid_from', 'valid_until', 'confidence', 'revoked', 'tags', 'tlp'):
                with self.subTest(kind='IOC', field=field, value=value):
                    r = self.client.post('/api/analyze', json={'events_text': json.dumps(self.rows[0]),
                        'indicators': [{**self.ti[0], field: value}]}, headers=self.headers)
                    self.assertLess(r.status_code, 500, r.text)
            for field in ('schema_version', 'assets', 'operators', 'suppressions', 'protected_networks', 'analysis_window_seconds'):
                with self.subTest(kind='policy', field=field, value=value):
                    r = self.client.post('/api/analyze', json={'events_text': json.dumps(self.rows[0]),
                        'policy_config': {**self.cfg, field: value}}, headers=self.headers)
                    self.assertLess(r.status_code, 500, r.text)

    def test_bad_json_body_returns_400(self):
        for body in ('{"events_text":"x","events_text":"y"}', '{"a":NaN}',
                     '{"a":1e999}', '{"a":"\\ud800"}', '[' * 1000 + '0' + ']' * 1000):
            with self.subTest(body=body[:40]):
                r = self.client.post('/api/analyze', content=body,
                                     headers={**self.headers, 'Content-Type': 'application/json'})
                self.assertEqual(r.status_code, 400, r.text)

    def test_anonymous_posts_cannot_consume_work_slots(self):
        for path, expected in (('/api/health', 401), ('/', 405), ('/assets/file.js', 405)):
            with self.subTest(path=path):
                self.assertEqual(self.client.post(path, json={}).status_code, expected)

    def test_empty_policy_not_replaced_with_demo_authority(self):
        r = self.client.post('/api/analyze', json={'events_text': json.dumps(self.rows[0]),
                                                  'policy_config': {}}, headers=self.headers)
        self.assertEqual(r.status_code, 400)

    def test_default_import_has_no_demo_asset_response_authority(self):
        r = self.client.post('/api/analyze', json={'events_text': '\n'.join(map(json.dumps, self.rows)),
                                                  'indicators': self.ti}, headers=self.headers)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(any(a['executable'] for a in r.json()['plan']['actions']))

    def test_oversized_request_is_rejected(self):
        r = self.client.post('/api/demo', content=b'x' * (8 * 1024 * 1024 + 1), headers=self.headers)
        self.assertEqual(r.status_code, 413)

    def test_non_json_post_is_rejected(self):
        r = self.client.post('/api/demo', content='data=x', headers=self.headers)
        self.assertEqual(r.status_code, 415)

    def test_oversized_knowledge_query_is_rejected(self):
        r = self.client.get('/api/knowledge/search', params={'q': 'x' * 513}, headers=self.headers)
        self.assertEqual(r.status_code, 422)

    def test_workbench_limits_concurrent_writes(self):
        ready = threading.Barrier(3); release = threading.Event()
        original = engine.analyze
        def blocked(*args, **kwargs):
            ready.wait(timeout=5); release.wait(timeout=5)
            return original(*args, **kwargs)
        def post():
            with TestClient(self.app) as client:
                return client.post('/api/demo', json={}, headers=self.headers)
        with patch('sentinel_zt.api.engine.analyze', side_effect=blocked), ThreadPoolExecutor(2) as pool:
            pending = [pool.submit(post) for _ in range(2)]
            try:
                ready.wait(timeout=5)
                self.assertEqual(self.client.post('/api/demo', json={}, headers=self.headers).status_code, 429)
            finally:
                release.set()
            self.assertTrue(all(f.result(timeout=5).status_code == 200 for f in pending))

    def test_failed_analysis_creates_no_partial_case(self):
        r = self.client.post('/api/analyze', json={'events_text': json.dumps(self.rows[0]),
                                                  'indicators': [{}]}, headers=self.headers)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.client.get('/api/cases', headers=self.headers).json(), [])


if __name__ == '__main__':
    unittest.main()
