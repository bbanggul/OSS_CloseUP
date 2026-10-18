"""D07 durable transaction tests using an isolated on-disk SQLite test adapter.

This adapter verifies the coordinator's persistence contract, not PostgreSQL SQL,
the production schema, worker fencing, or the actual API.
"""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from app.priority import PriorityInputError
from app.priority_stage import PriorityStagePersistenceError, run_priority_stage
from test_priority import payload, finding, link, uid


class DurableTestStore:
    def __init__(self, path):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.executescript('''
            CREATE TABLE evidence(id TEXT PRIMARY KEY, body TEXT);
            CREATE TABLE evaluation(seq INTEGER PRIMARY KEY, id TEXT UNIQUE, body TEXT);
            CREATE TABLE priority(id TEXT, finding_id TEXT, package_id TEXT, value TEXT);
        ''')
        self.fail_evidence = self.fail_priority = self.fail_error = False
        self.calls = []

    def save_scan_evidence(self, record):
        self.calls.append('evidence')
        with self.conn:
            self.conn.execute('INSERT INTO evidence VALUES (?,?)',
                              (record['evaluation_id'], json.dumps(record)))
            if self.fail_evidence:
                raise OSError('evidence write unavailable')

    def save_priority_result(self, record):
        self.calls.append('priority')
        with self.conn:
            for row in record['result']['link_results']:
                self.conn.execute('INSERT INTO priority VALUES (?,?,?,?)',
                                  (record['evaluation_id'], row['finding_id'], row['package_id'], row['priority']))
                if self.fail_priority:
                    raise OSError('write interrupted after first priority row')
            self.conn.execute('INSERT INTO evaluation(id,body) VALUES (?,?)',
                              (record['evaluation_id'], json.dumps(record)))

    def save_priority_error(self, record):
        self.calls.append('error')
        with self.conn:
            self.conn.execute('INSERT INTO evaluation(id,body) VALUES (?,?)',
                              (record['evaluation_id'], json.dumps(record)))
            if self.fail_error:
                raise OSError('error ledger unavailable')

    def durable_rows(self, table):
        # A new connection proves data is committed, not just visible in-session.
        with sqlite3.connect(self.path) as reader:
            return reader.execute(f'SELECT * FROM {table} ORDER BY rowid').fetchall()


class PriorityStageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DurableTestStore(str(Path(self.tmp.name) / 'test.db'))
        self.addCleanup(self.store.conn.close)
        self.raw = {'trivy': {'original': ['raw advisory']}, 'osv': {'stderr': 'timeout'}}
        self.valid = {'findings': [{'severity': 'HIGH', 'raw_id': 'observed-1'}],
                      'manual_review': ['preserve warning']}
        self.tools = {'trivy': {'status': 'completed'}, 'osv': {'status': 'failed', 'error': 'timeout'}}

    def run_stage(self, data=None, builder=None):
        return run_priority_stage(scan_id=uid(1), attempt_id=uid(2),
                                  raw_results=self.raw, valid_results=self.valid, tool_status=self.tools,
                                  build_payload=builder or (lambda _: deepcopy(data)), store=self.store)

    def assert_evidence_saved(self):
        rows = self.store.durable_rows('evidence')
        self.assertTrue(rows)
        for _, body in rows:
            row = json.loads(body)
            self.assertEqual(row['raw_results'], self.raw)
            self.assertEqual(row['valid_results'], self.valid)
            self.assertEqual(row['tool_status'], self.tools)

    def test_invalid_link_blocks_entire_priority_batch_but_commits_valid_scan_results(self):
        data = payload(findings=[finding(201), finding(202)], links=[link(), link(202, pid=999)])
        outcome = self.run_stage(data)
        self.assertEqual(outcome['status'], 'invalid_input')
        self.assertEqual(outcome['error']['code'], 'UNKNOWN_PACKAGE_ID')
        self.assertEqual(outcome['error']['field_path'], 'finding_packages[1].package_id')
        self.assertEqual(outcome['attempted_payload'], data)
        self.assertFalse(outcome['priority_saved'])
        self.assertFalse(outcome['current_result_available'])
        self.assertIsNone(outcome['result'])
        self.assertEqual(self.store.calls, ['evidence', 'error'])
        self.assertEqual(self.store.durable_rows('priority'), [])
        self.assertEqual(len(self.store.durable_rows('evaluation')), 1)
        self.assert_evidence_saved()

    def test_candidate_mismatch_preserves_raw_candidates_and_error(self):
        data = payload()
        data['finding_packages'][0]['fix_information'] = 'candidates_available'
        outcome = self.run_stage(data)
        self.assertEqual(outcome['error']['code'], 'FIX_INFORMATION_MISMATCH')
        self.assertTrue(outcome['error_saved'])
        self.assert_evidence_saved()
        error = json.loads(self.store.durable_rows('evaluation')[0][2])
        self.assertEqual(error['attempted_payload'], data)

    def test_input_build_error_happens_after_evidence_commit(self):
        def broken_builder(evidence):
            self.assert_evidence_saved()
            raise PriorityInputError('ID_MAPPING_FAILED', 'finding_packages', 'Missing DB mapping')
        outcome = self.run_stage(builder=broken_builder)
        self.assertEqual(outcome['error']['stage'], 'input_build')
        self.assertEqual(outcome['error']['code'], 'ID_MAPPING_FAILED')
        self.assertEqual(outcome['status'], 'invalid_input')
        self.assertIsNone(outcome['attempted_payload'])
        self.assertEqual(self.store.durable_rows('priority'), [])

    def test_unexpected_builder_error_is_failed_not_empty_success(self):
        def broken_builder(_):
            raise RuntimeError('input lookup unavailable')
        outcome = self.run_stage(builder=broken_builder)
        self.assertEqual(outcome['status'], 'failed')
        self.assertEqual(outcome['error']['code'], 'PRIORITY_INPUT_BUILD_FAILED')
        self.assertIsNone(outcome['result'])
        self.assert_evidence_saved()

    def test_priority_write_rollback_does_not_rollback_evidence_or_error_record(self):
        self.store.fail_priority = True
        outcome = self.run_stage(payload(findings=[finding(201), finding(202)], links=[link(), link(202)]))
        self.assertEqual(outcome['error']['code'], 'PRIORITY_WRITE_FAILED')
        self.assertEqual(self.store.calls, ['evidence', 'priority', 'error'])
        self.assertEqual(self.store.durable_rows('priority'), [])
        errors = self.store.durable_rows('evaluation')
        self.assertEqual(len(errors), 1)
        self.assertEqual(json.loads(errors[0][2])['status'], 'failed')
        self.assert_evidence_saved()

    def test_previous_success_is_history_not_replacement_for_current_invalid_result(self):
        first = self.run_stage(payload())
        old_priorities = self.store.durable_rows('priority')
        data = payload(findings=[finding(severity='INFO')])
        second = self.run_stage(data)
        self.assertNotEqual(first['evaluation_id'], second['evaluation_id'])
        self.assertEqual(self.store.durable_rows('priority'), old_priorities)
        history = [json.loads(row[2]) for row in self.store.durable_rows('evaluation')]
        self.assertEqual([r['status'] for r in history], ['completed', 'invalid_input'])
        self.assertFalse(history[-1]['current_result_available'])
        self.assertIsNone(history[-1]['result'])
        self.assert_evidence_saved()

    def test_retry_after_error_keeps_error_history_and_publishes_valid_priority(self):
        bad = self.run_stage(payload(findings=[finding(severity='INFO')]))
        good = self.run_stage(payload())
        self.assertEqual(bad['status'], 'invalid_input')
        self.assertEqual(good['status'], 'completed')
        self.assertEqual(good['result']['link_results'][0]['priority'], 'P1')
        self.assertEqual(len(self.store.durable_rows('evaluation')), 2)
        self.assertEqual(len(self.store.durable_rows('priority')), 1)
        self.assert_evidence_saved()

    def test_normal_partial_and_failed_security_stay_separate_from_priority_stage(self):
        for security, expected in [('completed', 'no_findings'), ('partial', 'unavailable'), ('failed', 'unavailable')]:
            with self.subTest(security=security):
                out = self.run_stage(payload(status=security, findings=[], links=[]))
                self.assertEqual(out['status'], 'completed')
                self.assertEqual(out['result']['security_status'], security)
                self.assertEqual(out['result']['package_results'][0]['priority_status'], expected)
        partial = self.run_stage(payload(status='partial'))
        self.assertEqual(partial['result']['link_results'][0]['priority'], 'P1')
        self.assertTrue(partial['result']['package_results'][0]['incomplete'])

    def test_unknown_is_a_valid_null_result_not_an_input_failure(self):
        out = self.run_stage(payload(findings=[finding(severity='UNKNOWN')]))
        self.assertTrue(out['priority_saved'])
        self.assertFalse(out['error_saved'])
        self.assertEqual(out['result']['link_results'][0]['priority_status'], 'severity_unknown')
        self.assertIsNone(self.store.durable_rows('priority')[0][3])

    def test_test_data_and_other_scan_cannot_be_published(self):
        for changed, code in [({'test_only': True}, 'TEST_DATA_NOT_ALLOWED'),
                              ({'scan_id': uid(999)}, 'SCAN_SCOPE_MISMATCH')]:
            data = payload()
            data.update(changed)
            outcome = self.run_stage(data)
            self.assertEqual(outcome['error']['code'], code)
            self.assertFalse(outcome['priority_saved'])
            self.assertEqual(self.store.durable_rows('priority'), [])

    def test_error_persistence_failure_is_raised_with_record_and_raw_is_still_saved(self):
        self.store.fail_error = True
        with self.assertRaises(PriorityStagePersistenceError) as caught:
            self.run_stage(payload(findings=[finding(severity='INFO')]))
        self.assertEqual(caught.exception.stage, 'priority_error')
        self.assertTrue(caught.exception.scan_evidence_saved)
        self.assertEqual(caught.exception.record['error']['code'], 'INVALID_VALUE')
        self.assertEqual(self.store.durable_rows('evaluation'), [])
        self.assert_evidence_saved()

    def test_evidence_write_failure_stops_priority_without_claiming_preservation(self):
        self.store.fail_evidence = True
        with self.assertRaises(PriorityStagePersistenceError) as caught:
            self.run_stage(payload())
        self.assertFalse(caught.exception.scan_evidence_saved)
        self.assertEqual(caught.exception.stage, 'scan_evidence')
        self.assertEqual(caught.exception.record['raw_results'], self.raw)
        self.assertEqual(self.store.calls, ['evidence'])
        self.assertEqual(self.store.durable_rows('priority'), [])

    def test_builder_cannot_mutate_saved_evidence_or_callers_input(self):
        before = deepcopy((self.raw, self.valid, self.tools))
        def builder(record):
            record['raw_results'].clear()
            record['valid_results'].clear()
            record['tool_status'].clear()
            return payload()
        out = self.run_stage(builder=builder)
        self.assertTrue(out['priority_saved'])
        self.assertEqual((self.raw, self.valid, self.tools), before)
        self.assert_evidence_saved()

    def test_unexpected_calculator_failure_retains_error_evidence(self):
        with patch('app.priority_stage.calculate_priorities', side_effect=RuntimeError('calculation failure')):
            out = self.run_stage(payload())
        self.assertEqual(out['status'], 'failed')
        self.assertEqual(out['error']['code'], 'PRIORITY_CALCULATION_FAILED')
        self.assert_evidence_saved()
