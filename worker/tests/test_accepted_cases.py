"""29 original IDs, executable module expectations; no DB/UI acceptance claim.

Missing reported candidates and abstract ages are explicitly synthetic fixtures.
The historical proposed_expected is kept for traceability, never overwritten by
actual results. D07 IDs exercise existing calculator behavior only.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest

from app.normalizer import normalize_results
from app.priority import calculate_priorities
from app.review_policy import evaluate_activity, evaluate_license
from test_priority import payload, package, finding, link


CASES = json.loads((Path(__file__).resolve().parents[2] / 'docs/priority-engine/accepted-cases.json').read_text())['cases']
if len(CASES) != 29 or len({case['id'] for case in CASES}) != 29:
    raise ValueError('Expected all 29 distinct original case IDs')


def security_input(original):
    raw_severity = original.get('raw_severity', original.get('severity'))
    candidates = original.get('fixed_version_candidates', [])
    if original.get('fix_status') == 'reported':
        candidates = ['1.1.0']  # Test-only placeholder, never an observed remediation.
    raw = {'VulnerabilityID': 'EXAMPLE-ACCEPTANCE', 'PkgName': 'demo', 'InstalledVersion': '1.0.0',
           'Severity': raw_severity, 'FixedVersion': ', '.join(candidates)}
    normalized = normalize_results(
        {'dependencies': {'demo': '1.0.0'}},
        {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/demo': {'version': '1.0.0'}}},
        {'trivy': {'SchemaVersion': 2, 'Results': [{'Type': 'npm', 'Vulnerabilities': [raw]}]},
         'osv': {'results': []}},
        {t: {'status': 'completed'} for t in ('trivy', 'osv')}, scan_id='synthetic-case')
    f = normalized['findings'][0]
    relationship = {True: 'direct', False: 'indirect', None: 'unknown'}[original.get('is_direct')]
    data = payload(packages=[package(relationship=relationship)], findings=[finding(severity=f['severity'])],
                   links=[link(fix=f['fix_information'])])
    data['test_only'] = True
    data['findings'][0].update({k: deepcopy(f[k]) for k in ('severity_observations', 'severity_conflict',
                                                         'priority_input_eligible', 'review_reasons', 'evidence')})
    data['finding_packages'][0]['fixed_version_candidates'] = deepcopy(f['fixed_version_candidates'])
    for c in data['finding_packages'][0]['fixed_version_candidates']:
        c['test_only'] = True
    return data


def check_case(test, case):
    cid, original, expected = case['id'], case['original_input'], case['proposed_expected']
    if cid in ('B01', 'B02') or cid.startswith('S'):
        data = security_input(original)
        result = calculate_priorities(data, allow_test_data=True)
        row, aggregate = result['link_results'][0], result['package_results'][0]
        for key in ('priority', 'priority_status', 'has_fix_candidate', 'fix_information', 'priority_rule_version'):
            test.assertEqual(row[key], expected[key])
        test.assertEqual(data['findings'][0]['severity'], expected['severity'])
        test.assertEqual(aggregate['incomplete'], expected['incomplete'])
        if 'raw_severity' in expected:
            test.assertEqual(row['finding_context']['severity_observations'][0]['raw'], expected['raw_severity'])
        if cid == 'S08':
            test.assertEqual(result['summary']['unknown_finding_count'], 1)
            test.assertEqual(aggregate['representative_finding_ids'], [])
            test.assertFalse(aggregate['has_fix_candidate_at_priority'])
        if cid in ('S09', 'S10'):
            test.assertEqual([c['value'] for c in row['fixed_version_candidates']], original['fixed_version_candidates'])
            test.assertNotIn('recommended_fixed_version', row)
        if cid == 'S10':
            test.assertEqual(data['packages'][0]['relationship'], 'unknown')
            test.assertNotIn('NSWG-ECO-516_requires_manual_review', row['finding_context']['review_reasons'])
    elif cid == 'B03' or cid.startswith('L'):
        values = original.get('dependency_licenses_to_test_individually', original.get(
            'expressions_to_test_individually', [original.get('dependency_license')]))
        for raw in values:
            with test.subTest(raw=raw):
                row = evaluate_license(raw, project_license=original.get('project_license'))
                test.assertEqual(row['raw_license'], raw)
                status = expected.get('each_license_status', {}).get(raw, expected.get('license_status', '확인 필요'))
                test.assertEqual(row['license_status'], status)
                test.assertEqual(row['security_priority_effect'], 'none')
                if 'reason_code' in expected:
                    test.assertEqual(row['reason_code'], expected['reason_code'])
                if cid == 'L05':
                    e = next(e for e in expected['expression_results'] if e['raw'] == raw)
                    test.assertEqual(row['expression'], {'operator': e['operator'], 'operands': e['operands']})
                    test.assertEqual(row['reason_code'], e['reason_code'])
                    test.assertIsNone(row['automatic_selection'])
    elif cid == 'B04' or cid.startswith('M'):
        facts = deepcopy(original)
        now = datetime(2026, 9, 27, tzinfo=timezone.utc)
        as_of = original.get('as_of') if cid == 'B04' else now.isoformat()
        # Abstract age examples are concretized only inside tests, not production.
        for short in ('commit', 'release'):
            if f'last_{short}_age' in facts:
                days = {'1일': 1, '8개월': 243}[facts[f'last_{short}_age']]
                facts[f'last_{short}_at'] = (now - timedelta(days=days)).isoformat()
        variants = (-1, 0, 1) if cid == 'M04' else (0,)
        for delta in variants:
            if cid == 'M04':
                facts['last_commit_at'] = (now - timedelta(days=243, seconds=delta)).isoformat()
            row = evaluate_activity(facts, as_of=as_of)
            test.assertEqual(row['maintenance_status'], expected.get('maintenance_status', 'Facts only'))
            test.assertFalse(row['automatic_risk_classification'])
            test.assertEqual(row['security_priority_effect'], 'none')
            for key in ('last_commit_at', 'last_release_at', 'archived', 'commit_elapsed_days', 'release_display'):
                if key in expected:
                    test.assertEqual(row[key], expected[key])
            if cid in ('M03', 'M05'):
                test.assertEqual(row['commit_elapsed_days'], 1 if cid == 'M03' else 243)
                test.assertEqual(row['release_elapsed_days'], 1)
    elif cid == 'X01':
        data = security_input({'severity': 'HIGH', 'is_direct': True, 'fix_status': 'reported'})
        for side in ('before', 'after'):
            data['findings'][0].update(original[side])
            row = calculate_priorities(data, allow_test_data=True)['link_results'][0]
            test.assertEqual(row['priority'], 'P1')
            test.assertEqual(evaluate_license(original[side]['license'])['license_status'], expected[side]['license_status'])
            test.assertNotIn('combined_risk_score', row)
    elif cid == 'X02':
        row = calculate_priorities(payload(findings=[finding(201, 'CRITICAL'), finding(202, 'MEDIUM')],
                                           links=[link(201), link(202)]))['package_results'][0]
        test.assertEqual(row['priority'], expected['package_priority'])
        test.assertEqual(len(row['representative_finding_ids']), expected['representative_count'])
    elif cid in ('X03', 'X04', 'X05'):
        data = payload(status=expected['security_status'], findings=[] if cid != 'X04' else [finding()],
                       links=[] if cid != 'X04' else [link(fix='unknown')])
        result = calculate_priorities(data)
        for key in ('priority', 'priority_status', 'incomplete'):
            test.assertEqual(result['package_results'][0][key], expected[key])
        test.assertEqual(result['summary']['finding_count'], expected['finding_count'])
    else:
        test.fail(f'Unimplemented case: {cid}')


class AcceptedCasesTests(unittest.TestCase):
    pass


def make_test(case):
    def test(self):
        check_case(self, case)
    return test


for case in CASES:
    setattr(AcceptedCasesTests, f'test_{case["id"]}', make_test(case))
