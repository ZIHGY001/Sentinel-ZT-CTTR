"""Third audit regressions: bound IOC lifetime, state files and source integrity."""
import itertools
import os
import socket
import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from sentinel_zt import demo, engine, events, intel, knowledge, response
from sentinel_zt.common import iso, timestamp, write_json

NOW = timestamp('2026-09-21T12:00:00Z')


class Audit3Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        rows, ti, self.cfg, _ = demo.fixtures(NOW)
        self.cfg['assets']['workstation-demo']['local_hostname'] = socket.gethostname()
        indicators = [intel.Indicator.parse({**x, 'valid_until': iso(NOW+timedelta(seconds=1))}) for x in ti]
        a = engine.analyze([events.canonical_event(x, 'test', i) for i, x in enumerate(rows)], indicators, NOW, self.cfg)
        self.plan = engine.make_plan(a, self.cfg, NOW)
        self.action = next(a for a in self.plan['actions'] if a['type']=='block_peer' and a['host']=='workstation-demo')
        self.key = b'x' * 32

    def test_expired_ioc_cannot_receive_approval(self):
        with self.assertRaisesRegex(ValueError, 'IOC is expired'):
            response.approve(self.plan, self.action['id'], self.cfg, 'lab-analyst', self.key, NOW+timedelta(seconds=2))

    def test_approval_deadline_is_capped_by_ioc_lifetime(self):
        token = response.approve(self.plan, self.action['id'], self.cfg, 'lab-analyst', self.key, NOW)
        self.assertEqual(timestamp(token['payload']['expires_at']), NOW+timedelta(seconds=1))

    def test_ioc_expiry_during_preflight_never_requests_change(self):
        token = response.approve(self.plan, self.action['id'], self.cfg, 'lab-analyst', self.key, NOW)
        calls = []
        def runner(script, check=False): calls.append(check)
        clock = iter([NOW, NOW+timedelta(seconds=2)])
        with patch('sentinel_zt.response.require_root'), self.assertRaisesRegex(RuntimeError, 'no firewall change'):
            response.apply(self.plan, token, self.cfg, self.key, NOW, self.root/'state', 'workstation-demo',
                           True, runner, clock=lambda:next(clock))
        self.assertEqual(calls, [True])

    def test_old_unbound_plan_is_refused(self):
        self.action.pop('intel_evidence')
        with self.assertRaisesRegex(ValueError, 're-analyze'):
            response.validate_action(self.plan, self.action, self.cfg, NOW)

    def test_ioc_support_must_bind_the_peer_and_observation(self):
        for field, value in [('value','203.0.113.99'), ('evidence_id','unrelated'), ('confidence',0), ('revoked',True)]:
            support = self.action['intel_evidence']; original = support[field] if field in support else None
            support[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                response.validate_action(self.plan, self.action, self.cfg, NOW)
            support[field] = original

    def test_journal_connect_failure_releases_lock(self):
        state = self.root/'state'
        with patch('sentinel_zt.response.sqlite3.connect', side_effect=sqlite3.OperationalError('synthetic')):
            with self.assertRaises(sqlite3.OperationalError): response.Journal(state, self.key)
        journal = response.Journal(state, self.key)
        self.assertTrue(journal.verify()['verified']); journal.close(); journal.close()

    def test_journal_schema_failure_closes_connection_and_lock(self):
        state = self.root/'state'
        with patch('sentinel_zt.response.sqlite3.connect') as connect:
            connect.return_value.execute.side_effect = sqlite3.OperationalError('synthetic')
            with self.assertRaises(sqlite3.OperationalError): response.Journal(state, self.key)
            connect.return_value.close.assert_called_once()
        journal = response.Journal(state, self.key); journal.close()

    @unittest.skipUnless(os.name == 'posix', 'POSIX hardlinks')
    def test_hardlinked_journal_and_lock_are_rejected(self):
        for name in ('response.sqlite3', 'response.lock'):
            state = self.root/name.replace('.', '-'); state.mkdir(mode=0o700)
            original = self.root/(name+'.original'); original.write_bytes(b''); original.chmod(0o600)
            os.link(original, state/name)
            with self.subTest(name=name), self.assertRaises(ValueError): response.Journal(state, self.key)
            self.assertEqual(original.read_bytes(), b'')

    @unittest.skipUnless(os.name == 'posix', 'POSIX permissions')
    def test_readable_journal_is_refused_without_changing_permissions(self):
        state = self.root/'state'; state.mkdir(mode=0o700)
        db = state/'response.sqlite3'; db.write_bytes(b''); db.chmod(0o644)
        with self.assertRaises(ValueError): response.Journal(state, self.key)
        self.assertEqual(db.stat().st_mode & 0o777, 0o644)

    @unittest.skipUnless(os.name == 'posix', 'POSIX FIFO')
    def test_fifo_and_hardlinked_keys_are_refused(self):
        fifo = self.root/'fifo'; os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError): response.key_bytes(fifo)
        key = self.root/'key'; key.write_bytes(self.key); key.chmod(0o600)
        other = self.root/'linked-key'; os.link(key, other)
        with self.assertRaises(ValueError): response.key_bytes(other)

    def test_article_path_escape_is_refused(self):
        targets = ['https://github.com/izj007/wechat/blob/main/articles/../../../../../other/repo',
                   'https://github.com/izj007/wechat/blob/main/articles/%252e%252e/file.md',
                   'https://github.com/izj007/wechat/blob/main/articles/..%5c..%5cother.md',
                   'https://github.com/izj007/wechat/blob/../articles/other.md',
                   'https://github.com/other/repo/blob/main/articles/file.md', 'articles/../file.md']
        for target in targets:
            with self.subTest(target=target):
                result=knowledge.index_readme(('- [reference]('+target+')').encode(), 'main', NOW)
                self.assertEqual(result['entries'], [])

    def test_unicode_article_urls_remain_canonical_and_deduplicated(self):
        raw='- [a](articles/应急.md)\n- [b](https://github.com/izj007/wechat/blob/main/articles/%E5%BA%94%E6%80%A5.md)'
        result=knowledge.index_readme(raw.encode(),'main',NOW)
        self.assertEqual(len(result['entries']),1)
        self.assertIn('%E5%BA%94%E6%80%A5.md',result['entries'][0]['url'])

    def test_dot_revisions_are_refused(self):
        for revision in ('.','..'):
            with self.assertRaises(ValueError): knowledge.index_readme(b'',revision,NOW)

    def test_stix_creator_gaps_cannot_hide_conflicts_in_any_order(self):
        base={'type':'indicator','id':'indicator--test','modified':iso(NOW),'pattern_type':'stix',
              'pattern':"[ipv4-addr:value = '203.0.113.50']",'valid_from':iso(NOW-timedelta(days=1))}
        records=[{**base,'created_by_ref':'identity--one'}, {**base,'modified':iso(NOW+timedelta(seconds=1))},
                 {**base,'modified':iso(NOW+timedelta(seconds=2)),'created_by_ref':'identity--two'}]
        for sequence in itertools.permutations(records):
            path=self.root/'stix.json'; write_json(path,{'type':'bundle','objects':list(sequence)})
            with self.assertRaisesRegex(ValueError,'creator'): intel.load_intel(path)


if __name__ == '__main__': unittest.main()
