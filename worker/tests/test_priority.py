"""Executable agreed security rules. All inputs are synthetic, not scan evidence."""

from copy import deepcopy
import json
from pathlib import Path
import random
import unittest

from app.priority import PriorityInputError, calculate_priorities


def uid(number):
    return f'00000000-0000-4000-8000-{number:012x}'


def package(number=101, name='example', version='1.0.0', relationship='direct'):
    return dict(package_id=uid(number), name=name, installed_version=version,
                relationship=relationship)


def finding(number=201, severity='HIGH'):
    return dict(finding_id=uid(number), severity=severity)


def link(fid=201, pid=101, fix='not_reported'):
    candidates = [{'value': '1.1.0', 'raw': '>=1.1.0', 'source_tool': 'trivy'}]
    return dict(finding_id=uid(fid), package_id=uid(pid), fix_information=fix,
                fixed_version_candidates=candidates if fix == 'candidates_available' else [])


def payload(packages=None, findings=None, links=None, status='completed'):
    return {
        'schema_version': 'priority-io-v2', 'scan_id': uid(1), 'security_status': status,
        'tool_status': {'trivy': {'status': 'completed' if status != 'failed' else 'failed'},
                        'osv': {'status': 'completed' if status == 'completed' else 'failed'}},
        'packages': [package()] if packages is None else packages,
        'findings': [finding()] if findings is None else findings,
        'finding_packages': [link()] if links is None else links,
    }


class PriorityTests(unittest.TestCase):
    def assert_input_error(self, data, code, path):
        before = deepcopy(data)
        with self.assertRaises(PriorityInputError) as caught:
            calculate_priorities(data)
        self.assertEqual((caught.exception.code, caught.exception.field_path), (code, path))
        self.assertEqual(data, before)

    def test_contract_example_exact_output(self):
        folder = Path(__file__).resolve().parents[2] / 'docs' / 'priority-engine'
        data = json.loads((folder / 'example-input.json').read_text())
        expected = json.loads((folder / 'example-expected.json').read_text())
        self.assertEqual(calculate_priorities(data, allow_test_data=True), expected)

    def test_all_severities_relationships_and_fix_states(self):
        # 5 severities x 3 relationships x 4 fix states = 60 independent inputs.
        for severity, expected in [('CRITICAL', 'P0'), ('HIGH', 'P1'),
                                   ('MEDIUM', 'P2'), ('LOW', 'P3'), ('UNKNOWN', None)]:
            for relationship in ('direct', 'indirect', 'unknown'):
                for fix in ('candidates_available', 'not_reported', 'unknown', 'failed'):
                    with self.subTest(severity=severity, relationship=relationship, fix=fix):
                        result = calculate_priorities(payload(
                            packages=[package(relationship=relationship)],
                            findings=[finding(severity=severity)], links=[link(fix=fix)]))
                        row, aggregate = result['link_results'][0], result['package_results'][0]
                        self.assertEqual(row['priority'], expected)
                        self.assertEqual(aggregate['priority'], expected)
                        self.assertEqual(row['has_fix_candidate'], fix == 'candidates_available')
                        self.assertEqual(row['priority_rule_version'], 'priority-v1')
                        self.assertEqual(aggregate['priority_status'],
                                         'severity_unknown' if expected is None else 'calculated')

    def test_b01_b02_critical_stays_before_high_with_fix(self):
        data = payload(
            packages=[package(103, 'a'), package(102, 'b', relationship='indirect'), package(101, 'z')],
            findings=[finding(203, 'HIGH'), finding(202, 'CRITICAL'), finding(201, 'CRITICAL')],
            links=[link(203, 103, 'candidates_available'), link(202, 102),
                   link(201, 101, 'candidates_available')])
        result = calculate_priorities(data)
        self.assertEqual([r['priority'] for r in result['link_results']], ['P0', 'P0', 'P1'])
        self.assertEqual([r['package_id'] for r in result['package_results']],
                         [uid(101), uid(102), uid(103)])

    def test_lower_severity_fix_does_not_promote_package(self):
        data = payload(packages=[package(101, 'a'), package(102, 'z')],
                       findings=[finding(201), finding(202, 'LOW'), finding(203)],
                       links=[link(), link(202, 101, 'candidates_available'),
                              link(203, 102, 'candidates_available')])
        rows = calculate_priorities(data)['package_results']
        self.assertEqual([r['package_id'] for r in rows], [uid(102), uid(101)])
        self.assertFalse(rows[1]['has_fix_candidate_at_priority'])
        self.assertEqual(rows[1]['representative_finding_ids'], [uid(201)])

    def test_all_representatives_sorted_and_any_fix_counts(self):
        data = payload(findings=[finding(203), finding(201), finding(202, 'MEDIUM')],
                       links=[link(203, fix='candidates_available'), link(), link(202)])
        row = calculate_priorities(data)['package_results'][0]
        self.assertEqual(row['priority'], 'P1')
        self.assertEqual(row['representative_finding_ids'], [uid(201), uid(203)])
        self.assertTrue(row['has_fix_candidate_at_priority'])

    def test_known_and_unknown_preserve_warning(self):
        row = calculate_priorities(payload(findings=[finding(), finding(202, 'UNKNOWN')],
                                           links=[link(), link(202)]))['package_results'][0]
        self.assertEqual((row['priority'], row['priority_status'], row['unknown_finding_count']),
                         ('P1', 'calculated', 1))

    def test_only_unknown_has_no_representatives_or_representative_fix(self):
        result = calculate_priorities(payload(findings=[finding(severity='UNKNOWN')],
                                              links=[link(fix='candidates_available')]))
        row = result['package_results'][0]
        self.assertEqual((row['priority'], row['priority_status']), (None, 'severity_unknown'))
        self.assertEqual(row['representative_finding_ids'], [])
        self.assertEqual(row['unknown_finding_count'], 1)
        self.assertFalse(row['has_fix_candidate_at_priority'])
        self.assertTrue(result['link_results'][0]['has_fix_candidate'])

    def test_no_findings_statuses_are_distinct(self):
        for status, expected, incomplete in [('completed', 'no_findings', False),
                                              ('partial', 'unavailable', True),
                                              ('failed', 'unavailable', True)]:
            with self.subTest(status=status):
                result = calculate_priorities(payload(findings=[], links=[], status=status))
                self.assertEqual(result['security_status'], status)
                self.assertEqual(result['link_results'], [])
                self.assertEqual(result['package_results'][0], {
                    'package_id': uid(101), 'priority': None, 'priority_status': expected,
                    'representative_finding_ids': [], 'has_fix_candidate_at_priority': False,
                    'unknown_finding_count': 0, 'incomplete': incomplete,
                    'package_name': 'example', 'installed_version': '1.0.0', 'representative_links': []})

    def test_empty_inventory_has_no_invented_packages(self):
        result = calculate_priorities(payload(packages=[], findings=[], links=[]))
        self.assertEqual(result['package_results'], [])
        self.assertEqual(result['link_results'], [])

    def test_partial_success_preserves_fix_and_severity(self):
        for fix in ('candidates_available', 'not_reported'):
            with self.subTest(fix=fix):
                result = calculate_priorities(payload(status='partial', links=[link(fix=fix)]))
                row = result['package_results'][0]
                self.assertEqual(row['priority'], 'P1')
                self.assertTrue(row['incomplete'])
                self.assertEqual(row['has_fix_candidate_at_priority'], fix == 'candidates_available')

    def test_failed_with_linked_or_unmapped_findings_rejected(self):
        for links in ([link()], []):
            with self.subTest(links=bool(links)):
                self.assert_input_error(payload(status='failed', links=links),
                                        'FAILED_WITH_FINDINGS', 'findings')

    def test_unmapped_findings_retained_sorted_without_fake_links(self):
        data = payload(findings=[finding(203, 'UNKNOWN'), finding(201, 'CRITICAL')], links=[])
        result = calculate_priorities(data)
        self.assertEqual(result['unmapped_finding_ids'], [uid(201), uid(203)])
        self.assertEqual(result['link_results'], [])
        self.assertEqual(result['package_results'][0]['priority_status'], 'no_findings')
        # A per-package no_findings is not a scan-level zero-Finding conclusion.
        self.assertEqual(len(data['findings']), 2)

    def test_duplicate_installations_remain_separate(self):
        data = payload(packages=[package(102, relationship='indirect'), package(101)],
                       links=[link(pid=102, fix='candidates_available'), link()])
        rows = calculate_priorities(data)['package_results']
        self.assertEqual([r['package_id'] for r in rows], [uid(102), uid(101)])
        self.assertEqual([r['has_fix_candidate_at_priority'] for r in rows], [True, False])

    def test_shared_unknown_is_counted_once_per_package_not_merged(self):
        data = payload(packages=[package(101), package(102)],
                       findings=[finding(severity='UNKNOWN')], links=[link(), link(pid=102)])
        result = calculate_priorities(data)
        self.assertEqual([r['unknown_finding_count'] for r in result['package_results']], [1, 1])
        self.assertEqual(result['unmapped_finding_ids'], [])
        # API/UI must use the one unique input Finding, not sum package counts.
        self.assertEqual(len(data['findings']), 1)

    def test_non_candidate_fix_states_have_equal_rank(self):
        data = payload(packages=[package(101, 'a'), package(102, 'b'), package(103, 'c')],
                       findings=[finding(201), finding(202), finding(203)],
                       links=[link(203, 103), link(202, 102, 'unknown'), link(201, 101, 'failed')])
        result = calculate_priorities(data)
        for key in ('link_results', 'package_results'):
            self.assertEqual([r['package_id'] for r in result[key]], [uid(101), uid(102), uid(103)])

    def test_unknown_links_and_packages_ignore_candidates(self):
        data = payload(packages=[package(101, 'a'), package(102, 'z')],
                       findings=[finding(201, 'UNKNOWN'), finding(202, 'UNKNOWN')],
                       links=[link(202, 102, 'candidates_available'), link()])
        result = calculate_priorities(data)
        for key in ('link_results', 'package_results'):
            self.assertEqual([r['package_id'] for r in result[key]], [uid(101), uid(102)])

    def test_case_sensitive_name_lexical_version_null_and_id_ties(self):
        packages = [package(106, 'b'), package(105, 'a', '2.0'), package(104, 'a', '10.0'),
                    package(103, 'a', None), package(102, 'a', ''), package(101, 'A')]
        data = payload(packages=packages, links=[link(pid=n) for n in range(101, 107)])
        result = calculate_priorities(data)
        expected = [uid(n) for n in (101, 102, 103, 104, 105, 106)]
        for key in ('link_results', 'package_results'):
            self.assertEqual([r['package_id'] for r in result[key]], expected)

    def test_link_final_tie_uses_finding_then_package_id(self):
        data = payload(packages=[package(102), package(101)],
                       findings=[finding(202), finding(201)],
                       links=[link(202, 101), link(201, 102), link(201, 101)])
        rows = calculate_priorities(data)['link_results']
        self.assertEqual([(r['finding_id'], r['package_id']) for r in rows],
                         [(uid(201), uid(101)), (uid(201), uid(102)), (uid(202), uid(101))])

    def test_package_status_sections_follow_risk_and_unknown(self):
        for status, empty_status in [('completed', 'no_findings'), ('partial', 'unavailable')]:
            with self.subTest(status=status):
                data = payload(packages=[package(103, 'a'), package(102, 'b'), package(101, 'z')],
                               findings=[finding(201, 'LOW'), finding(202, 'UNKNOWN')],
                               links=[link(202, 102), link()], status=status)
                rows = calculate_priorities(data)['package_results']
                self.assertEqual([r['priority_status'] for r in rows],
                                 ['calculated', 'severity_unknown', empty_status])

    def test_empty_status_section_uses_same_name_version_id_order(self):
        for status in ('completed', 'partial', 'failed'):
            with self.subTest(status=status):
                rows = calculate_priorities(payload(packages=[package(103, 'b'), package(102, 'a'),
                                                              package(101, 'a')],
                                                    findings=[], links=[], status=status))['package_results']
                self.assertEqual([r['package_id'] for r in rows], [uid(101), uid(102), uid(103)])

    def test_permutations_are_deterministic_and_input_is_unchanged(self):
        data = payload(packages=[package(101), package(102), package(103)],
                       findings=[finding(201), finding(202, 'UNKNOWN'), finding(203, 'CRITICAL'),
                                 finding(204, 'LOW'), finding(205, 'UNKNOWN')],
                       links=[link(), link(202, 101), link(203, 102),
                              link(201, 102, 'candidates_available')])
        expected = calculate_priorities(data)
        for seed in range(20):
            shuffled = deepcopy(data)
            rng = random.Random(seed)
            for key in ('packages', 'findings', 'finding_packages'):
                rng.shuffle(shuffled[key])
            before = deepcopy(shuffled)
            self.assertEqual(calculate_priorities(shuffled), expected)
            self.assertEqual(shuffled, before)
        expected['package_results'][0]['representative_finding_ids'].append('changed')
        self.assertNotEqual(calculate_priorities(data), expected)

    def test_duplicate_package_id(self):
        data = payload(packages=[package(), package()])
        self.assert_input_error(data, 'DUPLICATE_PACKAGE_ID', 'packages[1].package_id')

    def test_uuid_equivalent_ids_cannot_bypass_duplicate_check(self):
        data = payload(packages=[package(), package()])
        data['packages'][1]['package_id'] = uid(101).replace('-', '').upper()
        self.assert_input_error(data, 'DUPLICATE_PACKAGE_ID', 'packages[1].package_id')

    def test_duplicate_finding_id(self):
        self.assert_input_error(payload(findings=[finding(), finding()]),
                                'DUPLICATE_FINDING_ID', 'findings[1].finding_id')

    def test_duplicate_link(self):
        self.assert_input_error(payload(links=[link(), link(fix='candidates_available')]),
                                'DUPLICATE_LINK', 'finding_packages[1]')

    def test_missing_reference(self):
        for row, code, field in [(link(fid=999), 'UNKNOWN_FINDING_ID', 'finding_id'),
                                 (link(pid=999), 'UNKNOWN_PACKAGE_ID', 'package_id')]:
            with self.subTest(field=field):
                self.assert_input_error(payload(links=[row]), code, f'finding_packages[0].{field}')

    def test_candidate_state_mismatch_in_both_directions(self):
        for fix in ('candidates_available', 'not_reported', 'unknown', 'failed'):
            with self.subTest(fix=fix):
                row = link(fix=fix)
                row['fixed_version_candidates'] = [] if fix == 'candidates_available' else [{'raw': '1.1', 'source_tool': 'trivy'}]
                self.assert_input_error(payload(links=[row]), 'FIX_INFORMATION_MISMATCH',
                                        'finding_packages[0].fix_information')

    def test_unsupported_severity_is_not_silently_reinterpreted(self):
        for severity in ('INFO', 'MODERATE', 'high', 'SAFE', ''):
            with self.subTest(severity=severity):
                self.assert_input_error(payload(findings=[finding(severity=severity)]),
                                        'INVALID_VALUE', 'findings[0].severity')

    def test_invalid_schema_status_relationship_and_fix_state(self):
        cases = []
        for field, value in [('schema_version', 'priority-io-v99'), ('security_status', 'running'),
                             ('security_status', 'queued')]:
            data = payload()
            data[field] = value
            cases.append((data, field))
        data = payload(packages=[package(relationship='root')])
        cases.append((data, 'packages[0].relationship'))
        data = payload(links=[link(fix='reported')])
        cases.append((data, 'finding_packages[0].fix_information'))
        for data, path in cases:
            with self.subTest(path=path):
                self.assert_input_error(data, 'INVALID_VALUE', path)

    def test_missing_required_field(self):
        for field in ('schema_version', 'scan_id', 'security_status', 'tool_status',
                      'packages', 'findings', 'finding_packages'):
            with self.subTest(field=field):
                data = payload()
                del data[field]
                self.assert_input_error(data, 'MISSING_FIELD', field)
        data = payload()
        del data['packages'][0]['installed_version']
        self.assert_input_error(data, 'MISSING_FIELD', 'packages[0].installed_version')

    def test_invalid_shapes_and_candidate_objects(self):
        cases = [(None, '$'), ([], '$')]
        for field in ('packages', 'findings', 'finding_packages'):
            data = payload()
            data[field] = {}
            cases.append((data, field))
            data = payload()
            data[field] = [None]
            cases.append((data, f'{field}[0]'))
        data = payload()
        data['finding_packages'][0]['fixed_version_candidates'] = ['1.1.0']
        cases.append((data, 'finding_packages[0].fixed_version_candidates[0]'))
        data = payload()
        data['packages'][0]['installed_version'] = 1
        cases.append((data, 'packages[0].installed_version'))
        data = payload()
        data['findings'][0]['severity'] = None
        cases.append((data, 'findings[0].severity'))
        for data, path in cases:
            with self.subTest(path=path):
                self.assert_input_error(data, 'INVALID_TYPE', path)

    def test_normalizer_ids_are_not_accepted_as_database_uuid(self):
        data = payload()
        data['packages'][0]['package_id'] = 'pkg_123'
        self.assert_input_error(data, 'INVALID_UUID', 'packages[0].package_id')
        data = payload()
        data['scan_id'] = 'not-a-scan-id'
        self.assert_input_error(data, 'INVALID_UUID', 'scan_id')

    def test_tool_status_shape_validated_without_recomputing_security_status(self):
        data = payload(status='failed', findings=[], links=[])
        data['tool_status'] = {tool: {'status': 'completed'} for tool in ('trivy', 'osv')}
        # Adapter may invalidate all scanner output because normalization failed.
        self.assertEqual(calculate_priorities(data)['package_results'][0]['priority_status'], 'unavailable')
        del data['tool_status']['osv']
        self.assert_input_error(data, 'MISSING_FIELD', 'tool_status.osv')
        data = payload()
        data['tool_status']['osv']['status'] = ''
        self.assert_input_error(data, 'INVALID_VALUE', 'tool_status.osv.status')

    def test_opaque_candidates_evidence_and_manual_review_are_preserved(self):
        data = payload(links=[link(fix='candidates_available')])
        data['findings'][0].update(manual_review_required=True, evidence={'raw': ['untouched']})
        data['finding_packages'][0]['fixed_version_candidates'] = [
            {'raw': '>=1.0, <2.0', 'kind': 'tool_expression', 'source_tool': 'trivy'},
            {'value': '3.0.0', 'source_tool': 'osv'}]
        data['finding_packages'][0]['recommended_fixed_version'] = None
        original = deepcopy(data)
        result = calculate_priorities(data)
        self.assertEqual(data, original)
        self.assertTrue(result['link_results'][0]['has_fix_candidate'])
        self.assertNotIn('recommended_fixed_version', result['link_results'][0])


if __name__ == '__main__':
    unittest.main()
