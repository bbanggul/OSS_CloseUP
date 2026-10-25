"""Service-flow unit tests with a fake DB; not a PostgreSQL integration test."""
import importlib
import sys
import types
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_ai_generation import fixture, selection
from app.ai_generation import GenerationError, fingerprint


class HTTPException(Exception):
    def __init__(self, status_code, detail):
        self.status_code = status_code
        self.detail = detail


class ServiceTests(unittest.TestCase):
    def setUp(self):
        # Isolate test dependencies; production imports remain real FastAPI/psycopg.
        fake = {
            "fastapi": types.SimpleNamespace(HTTPException=HTTPException),
            "psycopg.rows": types.SimpleNamespace(dict_row=object()),
            "psycopg.types.json": types.SimpleNamespace(Jsonb=lambda x: x),
            "app.db": types.SimpleNamespace(connect=None),
        }
        with patch.dict(sys.modules, fake):
            sys.modules.pop("app.ai_service", None)
            self.service = importlib.import_module("app.ai_service")
        self.conn = MagicMock()
        self.conn.execute.return_value.fetchone.return_value = (True,)
        self.cur = self.conn.cursor.return_value.__enter__.return_value
        self.sid = UUID(int=1)
        self.real_snapshot = self.service.snapshot_for
        self.s = fixture()
        self.stack = []
        for name, value in [("connect", None), ("snapshot_for", self.s), ("config", ("test", "model")),
                            ("call_model", (selection(self.s), {"total_tokens": 10}))]:
            p = patch.object(self.service, name, return_value=value)
            mock = p.start()
            self.addCleanup(p.stop)
            if name == "connect":
                mock.return_value = MagicMock()
                mock.return_value.__enter__.return_value = self.conn
            if name == "call_model":
                self.provider = mock

    def test_success_commits_running_before_call(self):
        self.cur.fetchone.side_effect = [None, {"analysis_id": "a"}, {"status": "succeeded"}]
        self.provider.side_effect = lambda *args: (self.assertGreaterEqual(self.conn.commit.call_count, 2)
                                                   or selection(self.s), {"total_tokens": 10})
        self.assertEqual(self.service.generate(self.sid)["status"], "succeeded")
        self.assertTrue(any("pg_advisory_unlock" in str(c) for c in self.conn.execute.call_args_list))

    def test_identical_success_reused_without_charge(self):
        row = {"status": "succeeded", "input_fingerprint": fingerprint(self.s), "attempt_no": 1}
        self.cur.fetchone.return_value = row
        self.assertEqual(self.service.generate(self.sid), row)
        self.provider.assert_not_called()

    def test_concurrent_request_rejected(self):
        self.conn.execute.return_value.fetchone.return_value = (False,)
        with self.assertRaises(HTTPException) as e:
            self.service.generate(self.sid)
        self.assertEqual(e.exception.status_code, 409)
        self.provider.assert_not_called()

    def test_attempt_limit_no_charge(self):
        self.cur.fetchone.return_value = {"status": "failed", "attempt_no": 3}
        with self.assertRaises(HTTPException) as e:
            self.service.generate(self.sid)
        self.assertEqual(e.exception.status_code, 429)
        self.provider.assert_not_called()

    def test_failed_provider_recorded(self):
        self.cur.fetchone.side_effect = [None, {"analysis_id": "a"}, {"status": "failed"}]
        self.provider.side_effect = GenerationError("timeout")
        self.assertEqual(self.service.generate(self.sid)["status"], "failed")
        params = self.cur.execute.call_args.args[1]
        self.assertEqual(params[0], "failed")
        self.assertEqual(params[3], "timeout")
        self.assertIsNone(params[1])

    def test_invalid_output_not_saved_as_success(self):
        self.cur.fetchone.side_effect = [None, {"analysis_id": "a"}, {"status": "rejected"}]
        self.provider.return_value = ({"items": []}, {})
        self.service.generate(self.sid)
        params = self.cur.execute.call_args.args[1]
        self.assertEqual(params[0], "rejected")
        self.assertIsNone(params[1])

    def test_empty_scan_no_charge(self):
        self.s["items"] = []
        with self.assertRaises(HTTPException) as e:
            self.service.generate(self.sid)
        self.assertEqual(e.exception.status_code, 409)
        self.provider.assert_not_called()

    def test_finding_generation_has_separate_cache_and_storage_scope(self):
        fid = UUID(int=2)
        self.cur.fetchone.side_effect = [None, {"analysis_id": "a"}, {"status": "succeeded"}]
        self.service.generate(self.sid, fid)
        self.service.snapshot_for.assert_called_once_with(self.conn, self.sid, fid)
        queries = self.cur.execute.call_args_list
        self.assertEqual(queries[0].args[1][:3], (self.sid, 'finding', fid))
        insert = next(c for c in queries if 'INSERT INTO' in c.args[0])
        self.assertEqual(insert.args[1][:3], (self.sid, 'finding', fid))

    def test_report_cache_does_not_query_finding_scope(self):
        self.cur.fetchone.return_value = {'status': 'succeeded', 'input_fingerprint': fingerprint(self.s), 'attempt_no': 1}
        self.service.generate(self.sid)
        self.assertEqual(self.cur.execute.call_args.args[1][:3], (self.sid, 'scan_report', None))

    def test_legacy_success_is_stale_without_provider_call(self):
        self.assertTrue(self.service.stale_report(self.sid, {'status': 'succeeded', 'prompt_version': 'scan-evidence-v1'}))
        self.provider.assert_not_called()

    def test_snapshot_selects_only_target_finding(self):
        fid = UUID(int=2)
        self.cur.fetchone.return_value = {'status': 'completed'}
        self.cur.fetchall.side_effect = [[], [dict(self.s['items'][0])]]
        result = self.real_snapshot(self.conn, self.sid, fid)
        self.assertEqual(result['finding_count'], 1)
        query, args = self.cur.execute.call_args.args
        self.assertIn('f.finding_id=%s', query)
        self.assertEqual(args[:3], (self.sid, fid, fid))

    def test_report_snapshot_counts_more_than_thirty(self):
        self.cur.fetchone.return_value = {'status': 'completed'}
        self.cur.fetchall.side_effect = [[], [dict(self.s['items'][0], finding_id=str(i)) for i in range(45)]]
        with patch('app.ai_narrative.snapshot_for_report', return_value={'layout': 'package-v1'}) as build:
            result = self.real_snapshot(self.conn, self.sid)
        self.assertEqual(len(build.call_args.args[4]), 45)
        self.assertEqual(result['layout'], 'package-v1')

    def test_missing_finding_rejected_before_generation(self):
        self.cur.fetchone.return_value = {'status': 'completed'}
        self.cur.fetchall.side_effect = [[], []]
        with self.assertRaises(HTTPException) as caught:
            self.real_snapshot(self.conn, self.sid, UUID(int=3))
        self.assertEqual(caught.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
