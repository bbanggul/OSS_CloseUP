from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest

from app.review_policy import evaluate_activity, evaluate_license


class ReviewPolicyTests(unittest.TestCase):
    def test_general_is_not_no_obligations(self):
        for license_id in ('MIT', 'Apache-2.0', 'BSD-3-Clause', 'ISC'):
            with self.subTest(license_id=license_id):
                row = evaluate_license(license_id)
                self.assertEqual(row['license_status'], '일반')
                self.assertIn('조건 확인', row['reason'])
                self.assertFalse(row['legal_compliance_guarantee'])

    def test_original_suffixes_and_project_license_survive(self):
        for text in ('GPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later', 'LGPL-2.1-only', 'AGPL-3.0'):
            with self.subTest(text=text):
                row = evaluate_license(text, project_license='MIT')
                self.assertEqual(row['raw_license'], text)
                self.assertEqual(row['project_license'], 'MIT')
                self.assertEqual(row['reason_code'], 'copyleft_review')
                self.assertFalse(row['legal_violation_assertion'])

    def test_binary_expression_does_not_choose_or_flatten(self):
        for op, reason in [('OR', 'alternative_selection_review'), ('AND', 'combined_terms_review')]:
            raw = f'  MIT {op} GPL-3.0-only  '
            row = evaluate_license(raw)
            self.assertEqual(row['raw_license'], raw)
            self.assertEqual(row['expression'], {'operator': op, 'operands': ['MIT', 'GPL-3.0-only']})
            self.assertEqual(row['reason_code'], reason)
            self.assertIsNone(row['automatic_selection'])

    def test_unparsed_expressions_preserve_raw(self):
        for raw in ('MIT OR', '(MIT OR GPL-3.0-only) AND ISC', 'MIT WITH exception', 'MIT AND OR', ['MIT']):
            with self.subTest(raw=raw):
                before = deepcopy(raw)
                row = evaluate_license(raw)
                self.assertEqual(row['reason_code'], 'expression_unparsed')
                self.assertEqual(row['raw_license'], before)
                self.assertIsNone(row['expression'])

    def test_activity_field_failure_keeps_successful_dates_and_archive(self):
        facts = {'github_status': 'ok', 'archived': True, 'last_commit_at': '2026-10-17T00:00:00Z',
                 'last_release_at': None, 'field_status': {'last_release_at': 'failed'},
                 'field_errors': {'last_release_at': {'kind': 'rate_limited'}}, 'deprecated': False}
        before = deepcopy(facts)
        row = evaluate_activity(facts, as_of='2026-10-18T00:00:00Z')
        self.assertEqual(row['maintenance_status'], 'Archived')
        self.assertEqual(row['commit_elapsed_days'], 1)
        self.assertEqual(row['release_display'], '확인 불가')
        self.assertEqual(row['release_error'], {'kind': 'rate_limited'})
        self.assertFalse(row['deprecated'])
        self.assertEqual(facts, before)
        row['evidence']['field_errors'].clear()
        self.assertEqual(facts, before)

    def test_failed_lookup_does_not_reuse_stale_archived_or_date(self):
        row = evaluate_activity({'github_status': 'failed', 'archived': True,
                                 'last_commit_at': '2020-01-01T00:00:00Z'}, as_of='2026-10-18T00:00:00Z')
        self.assertEqual(row['maintenance_status'], 'Unknown')
        self.assertIsNone(row['archived'])
        self.assertEqual(row['evidence']['archived'], True)
        self.assertEqual(row['commit_status'], 'unavailable')
        self.assertIsNone(row['commit_elapsed_days'])

    def test_invalid_archive_is_not_truthy(self):
        for archived in ('false', 0, 1, None):
            row = evaluate_activity({'github_status': 'ok', 'archived': archived}, as_of='2026-10-18T00:00:00Z')
            self.assertEqual(row['maintenance_status'], 'Unknown')

    def test_dates_utc_floor_future_and_missing(self):
        for value, status, age in [
            ('2026-10-18T09:00:00+09:00', 'available', 0),
            ('2026-10-17T00:00:01Z', 'available', 0),
            ('2026-10-17T00:00:00Z', 'available', 1),
            ('2026-10-18T00:00:01Z', 'future', None),
            ('2026-10-17T00:00:00', 'invalid', None), ('bad', 'invalid', None), (None, 'missing', None),
        ]:
            with self.subTest(value=value):
                row = evaluate_activity({'github_status': 'ok', 'archived': False, 'last_commit_at': value},
                                        as_of='2026-10-18T00:00:00Z')
                self.assertEqual((row['commit_status'], row['commit_elapsed_days']), (status, age))
                self.assertEqual(row['last_commit_at'], value)
                self.assertEqual(row['maintenance_status'], 'Facts only')
                self.assertEqual(row['release_display'], '정보 없음')

    def test_arbitrary_old_threshold_never_classifies_active_or_low(self):
        now = datetime(2026, 10, 18, tzinfo=timezone.utc)
        for seconds in (1, 86400 * 243 - 1, 86400 * 243, 86400 * 243 + 1, 86400 * 3000):
            row = evaluate_activity({'github_status': 'ok', 'archived': False,
                                     'last_commit_at': (now - timedelta(seconds=seconds)).isoformat(),
                                     'last_release_at': now.isoformat()}, as_of=now.isoformat())
            self.assertEqual(row['maintenance_status'], 'Facts only')
            self.assertFalse(row['automatic_risk_classification'])
            self.assertFalse(row['threshold_enabled'])
            self.assertEqual(row['release_elapsed_days'], 0)

    def test_as_of_must_be_fixed_and_timezone_aware(self):
        for now in (None, '고정 시각', '2026-10-18'):
            with self.assertRaises(ValueError):
                evaluate_activity({}, as_of=now)
