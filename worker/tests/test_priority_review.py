from copy import deepcopy
import unittest

from app.priority import PriorityInputError, calculate_priorities
from test_priority import payload, package, finding, link, uid


class PriorityReviewTests(unittest.TestCase):
    def test_unique_counts_include_unmapped_without_double_counting_shared_finding(self):
        data = payload(packages=[package(101), package(102), package(103)],
                       findings=[finding(201, 'UNKNOWN'), finding(202, 'UNKNOWN'), finding(203, 'HIGH')],
                       links=[link(201, 101), link(201, 102), link(203, 102)])
        row = calculate_priorities(data)
        self.assertEqual(row['summary'], {'finding_count': 3, 'unknown_finding_count': 2,
                                         'package_count': 3, 'affected_package_count': 2,
                                         'unknown_package_count': 2, 'link_count': 3})
        self.assertEqual(row['unmapped_finding_ids'], [uid(202)])

    def test_representative_links_cannot_borrow_another_package_or_lower_grade_fix(self):
        data = payload(packages=[package(101, 'a'), package(102, 'b')],
                       findings=[finding(201), finding(202, 'LOW')],
                       links=[link(201, 101), link(202, 101, 'candidates_available'),
                              link(201, 102, 'candidates_available')])
        data['findings'][0].update(review_reasons=['manual'], evidence=[{'raw': 'original'}])
        before = deepcopy(data)
        rows = calculate_priorities(data)['package_results']
        by_id = {r['package_id']: r for r in rows}
        a, b = by_id[uid(101)], by_id[uid(102)]
        self.assertEqual(a['package_name'], 'a')
        self.assertEqual(a['priority'], 'P1')
        self.assertEqual(a['representative_links'][0]['fixed_version_candidates'], [])
        self.assertEqual(b['representative_links'][0]['package_name'], 'b')
        self.assertTrue(b['representative_links'][0]['fixed_version_candidates'])
        self.assertEqual(a['representative_links'][0]['finding_context']['review_reasons'], ['manual'])
        a['representative_links'][0]['finding_context']['evidence'].clear()
        self.assertEqual(data, before)

    def test_test_candidates_rejected_in_normal_call_even_if_payload_marked(self):
        data = payload(links=[link(fix='candidates_available')])
        data['finding_packages'][0]['fixed_version_candidates'][0]['test_only'] = True
        for flag in (False, True):
            data['test_only'] = flag
            with self.assertRaises(PriorityInputError) as caught:
                calculate_priorities(data)
            self.assertEqual(caught.exception.code, 'TEST_DATA_NOT_ALLOWED')
        result = calculate_priorities(data, allow_test_data=True)
        self.assertTrue(result['test_only'])
        self.assertTrue(result['link_results'][0]['fixed_version_candidates'][0]['test_only'])
        self.assertNotIn('recommended_fixed_version', result['link_results'][0])

    def test_reported_without_original_candidate_is_rejected(self):
        for candidate, code in [({}, 'EMPTY_FIX_CANDIDATE'),
                                ({'value': '  ', 'raw': ''}, 'EMPTY_FIX_CANDIDATE'),
                                ({'value': '1.0'}, 'MISSING_FIELD')]:
            data = payload(links=[link(fix='candidates_available')])
            data['finding_packages'][0]['fixed_version_candidates'] = [candidate]
            with self.assertRaises(PriorityInputError) as caught:
                calculate_priorities(data)
            self.assertEqual(caught.exception.code, code)

    def test_unsupported_severity_cannot_hide_behind_unknown(self):
        for fields in ({'priority_input_eligible': False},
                       {'severity_observations': [{'raw': 'INFO', 'normalized': 'UNKNOWN'}]}):
            data = payload(findings=[finding(severity='UNKNOWN')])
            data['findings'][0].update(fields)
            with self.assertRaises(PriorityInputError) as caught:
                calculate_priorities(data)
            self.assertEqual(caught.exception.code, 'SEVERITY_REVIEW_REQUIRED')

    def test_fix_status_and_link_warning_preserved_for_all_four_states(self):
        for state in ('candidates_available', 'not_reported', 'unknown', 'failed'):
            data = payload(links=[link(fix=state)])
            data['finding_packages'][0]['evidence'] = {'error': 'source unavailable', 'manual_review': True}
            row = calculate_priorities(data)['link_results'][0]
            self.assertEqual(row['fix_information'], state)
            self.assertEqual(row['link_evidence'], data['finding_packages'][0]['evidence'])
            self.assertEqual(row['priority'], 'P1')
