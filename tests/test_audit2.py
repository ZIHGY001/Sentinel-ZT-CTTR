"""Second secure-coding review: evidence age, parser ambiguity and response state."""
import copy
import hashlib
import itertools
import json
import socket
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from sentinel_zt import demo, engine, events, intel, policy, response, yunmai
from sentinel_zt.common import iso, load_json, now_utc, timestamp, write_json

NOW = timestamp('2026-09-21T12:00:00Z')


class AuditFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.rows, self.ti, self.cfg, self.req = demo.fixtures(NOW)
        self.iocs = [intel.Indicator.parse(x) for x in self.ti]
        self.mapping = load_json(Path(__file__).resolve().parent.parent / 'examples/yunmai-mapping.json')
        self.mapping['bindings'][0]['verified_at'] = iso(NOW)

    def analysis(self, behavior_age=100, peer_age=2):
        rows = [{**self.rows[0], 'timestamp': iso(NOW - timedelta(seconds=behavior_age))},
                {**self.rows[3], 'timestamp': iso(NOW - timedelta(seconds=peer_age))}]
        return engine.analyze([events.canonical_event(r, 'synthetic', i) for i, r in enumerate(rows)],
                              self.iocs, NOW, self.cfg)

    def plan(self, age=100):
        self.cfg['assets']['workstation-demo']['local_hostname'] = socket.gethostname()
        plan = engine.make_plan(self.analysis(age), self.cfg, NOW)
        return plan, next(a for a in plan['actions'] if a['type'] == 'block_peer')


class EvidenceFreshnessTests(AuditFixture):
    def test_old_behavior_cannot_be_refreshed_by_a_new_ioc(self):
        plan, action = self.plan(3600)
        self.assertFalse(action['executable'])
        self.assertIn('fresh_behavior_evidence_required', action['gates'])

    def test_new_ioc_in_correlation_is_not_fresh_behavior(self):
        analysis = self.analysis(901)
        self.assertIn('C001', analysis['incidents'][0]['rule_ids'])
        item = yunmai.handoff(analysis, self.mapping, NOW)['items'][0]
        self.assertEqual(item['status'], 'blocked')
        self.assertIn('fresh_behavior_evidence_required', item['gates'])

    def test_fresh_behavior_remains_actionable_with_approval(self):
        plan, action = self.plan()
        self.assertTrue(action['executable'])
        self.assertEqual(action['behavior_rule_id'], 'B001')
        token = response.approve(plan, action['id'], self.cfg, 'lab-analyst', b'x' * 32, NOW)
        self.assertEqual(response.verify_approval(plan, token, self.cfg, b'x' * 32, NOW)['id'], action['id'])

    def test_behavior_expires_even_while_peer_and_approval_are_fresh(self):
        plan, action = self.plan(899)
        self.assertTrue(action['executable'])
        with self.assertRaisesRegex(ValueError, 'behavior evidence is stale'):
            response.validate_action(plan, action, self.cfg, NOW + timedelta(seconds=2))

    def test_old_plan_without_behavior_binding_requires_reanalysis(self):
        plan, action = self.plan()
        for field in ('behavior_evidence_ids', 'behavior_rule_id', 'behavior_evidence_at'):
            action.pop(field)
        with self.assertRaisesRegex(ValueError, 're-analyze'):
            response.approve(plan, action['id'], self.cfg, 'lab-analyst', b'x' * 32, NOW)

    def test_aggregate_behavior_requires_all_observations_to_be_recent(self):
        analysis = self.analysis(901)
        for finding in analysis['findings']:
            if finding['rule_id'] == 'C001':
                finding['rule_id'] = 'B018'
        self.assertEqual(engine.fresh_behaviors(analysis, NOW, 900), {})

    def test_handoff_deadline_does_not_outlive_behavior(self):
        draft = yunmai.handoff(self.analysis(895), self.mapping, NOW)
        self.assertEqual(timestamp(draft['review_before']), NOW + timedelta(seconds=5))
        self.assertEqual(draft['items'][0]['review_before'], draft['review_before'])

    def test_handoff_deadline_does_not_outlive_mapping(self):
        self.mapping['bindings'][0]['verified_at'] = iso(NOW - timedelta(seconds=3595))
        draft = yunmai.handoff(self.analysis(), self.mapping, NOW)
        self.assertEqual(timestamp(draft['review_before']), NOW + timedelta(seconds=5))

    def test_whitespace_cannot_hide_protected_application(self):
        self.mapping['bindings'][0]['application_refs'] = [' app-sentinel-console ']
        with self.assertRaises(ValueError):
            yunmai.validate(self.mapping)

    def test_reanalysis_cannot_refresh_old_resource_telemetry(self):
        row = {**self.rows[-1], 'timestamp': iso(NOW - timedelta(hours=10))}
        a = engine.analyze([events.canonical_event(row, 'test', 1)], [], NOW, self.cfg)
        request = {**self.req, 'resource': row['host']}
        with self.assertRaisesRegex(ValueError, 'no fresh telemetry'):
            policy.access_from_analysis(request, self.cfg, a, NOW)

    def test_fresh_resource_telemetry_supports_normal_access(self):
        row = {**self.rows[-1], 'timestamp': iso(NOW - timedelta(seconds=1))}
        a = engine.analyze([events.canonical_event(row, 'test', 1)], [], NOW, self.cfg)
        request = {**self.req, 'resource': row['host']}
        self.assertEqual(policy.access_from_analysis(request, self.cfg, a, NOW)['decision'], 'allow')

    def test_non_object_access_request_is_a_validation_error(self):
        for request in (None, [], 'invalid'):
            with self.subTest(request=request), self.assertRaisesRegex(ValueError, 'access request'):
                policy.access_from_analysis(request, self.cfg, self.analysis(), NOW)


class ParserRegressionTests(AuditFixture):
    def indicator(self, **changes):
        return {'type': 'indicator', 'id': 'indicator--synthetic', 'modified': iso(NOW),
                'pattern_type': 'stix', 'pattern': "[ipv4-addr:value = '203.0.113.50']",
                'valid_from': iso(NOW - timedelta(hours=2)), **changes}

    def bundle(self, objects):
        path = self.root / 'bundle.json'
        write_json(path, {'type': 'bundle', 'objects': objects})
        return intel.load_intel(path)

    def test_utc_overflow_is_a_validation_error(self):
        for value in ('0001-01-01T00:00:00+01:00', '9999-12-31T23:59:59-01:00'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                timestamp(value)

    def test_default_stix_expiry_overflow_is_a_validation_error(self):
        with self.assertRaisesRegex(ValueError, 'default expiry'):
            self.bundle([self.indicator(valid_from='9999-12-31T23:59:59Z')])

    def test_unicode_separators_are_record_content(self):
        for separator in ('\u0085', '\u2028', '\u2029'):
            with self.subTest(separator=repr(separator)):
                line = json.dumps({**self.rows[0], 'note': 'first' + separator + 'second'}, ensure_ascii=False)
                path = self.root / 'unicode.jsonl'; path.write_text(line + '\r\n', encoding='utf-8')
                rows, _, stats = events.load_events([path])
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['note'], 'first' + separator + 'second')
                self.assertEqual(rows[0]['evidence']['raw_sha256'], hashlib.sha256(line.encode()).hexdigest())

    def test_log_line_limit_counts_bytes(self):
        path = self.root / 'large.jsonl'
        path.write_text(json.dumps({**self.rows[0], 'note': '中' * 350000}, ensure_ascii=False))
        with self.assertRaisesRegex(ValueError, 'line too long'):
            events.load_events([path])

    def test_conflicting_same_version_revocation_rejected_in_both_orders(self):
        objects = [self.indicator(), self.indicator(revoked=True)]
        for records in itertools.permutations(objects):
            with self.assertRaisesRegex(ValueError, 'conflicting STIX'):
                self.bundle(list(records))

    def test_revocation_cannot_be_undone_by_a_later_active_version(self):
        objects = [self.indicator(revoked=True), self.indicator(modified=iso(NOW + timedelta(seconds=1)))]
        for records in itertools.permutations(objects):
            rows, _ = self.bundle(list(records))
            self.assertTrue(rows[0].revoked)
            self.assertEqual(intel.IntelIndex(rows, NOW).ignored['revoked'], 1)

    def test_normal_newer_version_wins(self):
        objects = [self.indicator(), self.indicator(modified=iso(NOW + timedelta(seconds=1)),
                   pattern="[ipv4-addr:value = '203.0.113.51']")]
        for records in itertools.permutations(objects):
            rows, _ = self.bundle(list(records))
            self.assertEqual(rows[0].value, '203.0.113.51')

    def test_malformed_bundle_objects_are_validation_errors(self):
        for value in (None, {}, 'invalid', [None], [1], [{'type': 'indicator', 'id': []}]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.bundle(value)

    def test_unknown_revoked_pattern_cannot_silently_discard_revocation(self):
        with self.assertRaisesRegex(ValueError, 'revoked STIX'):
            self.bundle([self.indicator(revoked=True, pattern='unsupported pattern')])

    def test_red_tlp_marking_is_preserved(self):
        marking = {'type': 'marking-definition', 'id': 'marking-definition--synthetic',
                   'definition_type': 'tlp', 'definition': {'tlp': 'red'}}
        rows, _ = self.bundle([marking, self.indicator(object_marking_refs=[marking['id']])])
        self.assertEqual(rows[0].tlp, 'RED')

    def test_unresolved_marking_is_not_downgraded(self):
        rows, warnings = self.bundle([self.indicator(object_marking_refs=['marking-definition--missing'])])
        self.assertEqual(rows[0].tlp, 'RED')
        self.assertTrue(any('review original handling terms' in x for x in warnings))

    def test_conflicting_creator_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'creator'):
            self.bundle([self.indicator(created_by_ref='identity--one'),
                         self.indicator(modified=iso(NOW + timedelta(seconds=1)), created_by_ref='identity--two')])

    def test_duplicate_csv_columns_rejected(self):
        path = self.root / 'duplicate.csv'; path.write_text('type,value,value\nip,203.0.113.1,203.0.113.2\n')
        with self.assertRaisesRegex(ValueError, 'unique column'):
            intel.load_intel(path, 'csv')

    def test_ragged_or_unclosed_csv_rejected(self):
        for text in ('type,value\nip,203.0.113.1,extra\n', 'type,value\nip\n', '"unterminated'):
            with self.subTest(text=text):
                path = self.root / 'invalid.csv'; path.write_text(text)
                with self.assertRaises(ValueError):
                    intel.load_intel(path, 'csv')

    def test_url_zero_port_empty_credentials_and_zone_are_rejected(self):
        for value in ('http://example.test:0/', 'http://@example.test/', 'http://[2001:db8::1%lo]/'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                intel.normalize('url', value)


class ResponseStateTests(AuditFixture):
    def setUp(self):
        super().setUp()
        self.key = b'x' * 32; self.state = self.root / 'state'; self.calls = []
        self.plan_data, self.action = self.plan()
        self.approval = response.approve(self.plan_data, self.action['id'], self.cfg, 'lab-analyst', self.key, NOW)

    def runner(self, script, check=False):
        self.calls.append(check)

    def apply(self):
        with patch('sentinel_zt.response.require_root'):
            return response.apply(self.plan_data, self.approval, self.cfg, self.key, NOW, self.state,
                                  self.action['host'], True, self.runner, clock=lambda: NOW)

    def rollback(self, runner=None):
        with patch('sentinel_zt.response.require_root'):
            return response.rollback(self.action['id'], self.key, self.state, NOW, self.action['host'],
                                     True, runner or self.runner, lambda _: True)

    def test_deleted_action_cache_cannot_enable_replay(self):
        self.apply(); self.rollback()
        journal = response.Journal(self.state, self.key)
        try:
            journal.db.execute('DELETE FROM actions'); journal.db.commit()
        finally:
            journal.close()
        with self.assertRaisesRegex(ValueError, 'already journaled'):
            self.apply()
        self.assertEqual(self.calls, [True, False, False])

    def test_forged_rolled_back_cache_state_does_not_hide_live_action(self):
        self.apply()
        journal = response.Journal(self.state, self.key)
        try:
            journal.db.execute("UPDATE actions SET status='rolled_back'"); journal.db.commit()
        finally:
            journal.close()
        with self.assertRaisesRegex(ValueError, 'signed audit history'):
            self.rollback()

    def test_failed_rollback_has_durable_intent_and_uncertain_state(self):
        self.apply()
        def failure(script, check=False):
            raise TimeoutError('synthetic failure')
        with self.assertRaisesRegex(RuntimeError, 'rollback outcome uncertain'):
            self.rollback(failure)
        journal = response.Journal(self.state, self.key)
        try:
            self.assertTrue(journal.verify()['verified'])
            history = journal.history(self.action['id'])
            self.assertEqual([x['event'] for x in history[-2:]], ['rollback_intent', 'rollback_uncertain'])
            self.assertEqual(journal.db.execute('SELECT status FROM actions').fetchone()[0], 'rollback_uncertain')
        finally:
            journal.close()
        self.assertEqual(self.rollback()['status'], 'rolled_back')

    def test_successful_rollback_is_idempotent(self):
        self.apply(); self.rollback()
        self.assertEqual(self.rollback()['status'], 'already_rolled_back')
        self.assertEqual(self.calls, [True, False, False])


try:
    from fastapi.testclient import TestClient
    from sentinel_zt.api import create_app
    WEB_AVAILABLE = True
except ImportError:
    WEB_AVAILABLE = False


@unittest.skipUnless(WEB_AVAILABLE, 'install requirements-test.txt')
class Audit2APITests(AuditFixture):
    def setUp(self):
        super().setUp()
        self.client = TestClient(create_app(self.root / 'data', 't' * 32, testing=True), raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.headers = {'Authorization': 'Bearer ' + 't' * 32}
        self.rows, self.ti, self.cfg, _ = demo.fixtures(now_utc())

    def test_timestamp_overflow_returns_400(self):
        result = self.client.post('/api/analyze', json={'events_text': json.dumps({**self.rows[0],
                                  'timestamp': '0001-01-01T00:00:00+01:00'})}, headers=self.headers)
        self.assertEqual(result.status_code, 400)

    def test_unicode_log_import_retains_content(self):
        row = {**self.rows[0], 'note': 'first\u2028second'}
        result = self.client.post('/api/analyze', json={'events_text': json.dumps(row, ensure_ascii=False)}, headers=self.headers)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()['analysis']['events'][0]['note'], row['note'])

    def test_nested_event_and_suppression_types_do_not_return_500(self):
        values = [None, [], {}, True, 0, 1, 'bad', '', ['x']]
        for field in ('timestamp', 'host', 'event_type', 'process', 'parent_process', 'src_ip', 'dst_ip',
                      'src_port', 'dst_port', 'status', 'url', 'path', 'query', 'domain', 'authenticated',
                      'verified', 'authorized', 'file_path', 'sha256'):
            for value in values:
                with self.subTest(field=field, value=value):
                    result = self.client.post('/api/analyze', json={'events_text': json.dumps({**self.rows[0], field: value})},
                                              headers=self.headers)
                    self.assertLess(result.status_code, 500, result.text)
        for field in ('rule_id', 'host', 'reason', 'expires_at'):
            for value in values:
                with self.subTest(suppression=field, value=value):
                    suppression = {'rule_id': 'B001', 'host': 'h', 'reason': 'review', 'expires_at': iso(NOW), field: value}
                    result = self.client.post('/api/analyze', json={'events_text': json.dumps(self.rows[0]),
                            'policy_config': {**self.cfg, 'suppressions': [suppression]}}, headers=self.headers)
                    self.assertLess(result.status_code, 500, result.text)

    def handoff_setup(self):
        case = self.client.post('/api/demo', json={}, headers=self.headers).json()
        self.mapping['bindings'][0]['verified_at'] = iso(now_utc())
        mapping = self.root / 'mapping.json'; write_json(mapping, self.mapping)
        return '/api/cases/' + case['id'] + '/yunmai-handoff', {'SENTINEL_YUNMAI_MAPPING': str(mapping)}

    def test_handoff_file_count_cannot_grow_without_bound(self):
        route, env = self.handoff_setup()
        with patch.dict('os.environ', env), patch('sentinel_zt.api.MAX_HANDOFF_FILES', 1):
            self.assertEqual(self.client.post(route, json={}, headers=self.headers).status_code, 200)
            self.assertEqual(self.client.post(route, json={}, headers=self.headers).status_code, 409)
        self.assertEqual(len(list((self.root / 'data/handoffs').glob('*.json'))), 1)

    def test_handoff_byte_budget_rejects_before_write(self):
        route, env = self.handoff_setup()
        with patch.dict('os.environ', env), patch('sentinel_zt.api.MAX_HANDOFF_BYTES', 1):
            self.assertEqual(self.client.post(route, json={}, headers=self.headers).status_code, 409)
        self.assertFalse(list((self.root / 'data/handoffs').glob('*.json')))


if __name__ == '__main__':
    unittest.main()
