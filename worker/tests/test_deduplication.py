"""Synthetic reproductions, not the unavailable historical 74-finding scan."""
from copy import deepcopy
from collections import Counter
import unittest

import test_normalizer as base


class ExplicitIdentityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = base.NormalizerTests()
        self.fixture.setUp()

    def duplicates(self):
        f = self.fixture
        a = f.trivy_record(aid='CVE-a', ghsa='GHSA-same', Severity='HIGH', FixedVersion='1.1.0')
        b = f.trivy_record(aid='CVE-b', ghsa='GHSA-same', Severity='CRITICAL', FixedVersion='2.0.0')
        c = f.osv_record(aid='GHSA-same', aliases=['CVE-a', 'CVE-b'])
        return a, b, c

    def test_many_to_one_identity_merges_and_retains_all_evidence(self):
        originals = self.duplicates()
        r = self.fixture.run_normalize()
        self.assertEqual(len(r['findings']), 1)
        finding = r['findings'][0]
        self.assertEqual([e['raw'] for e in finding['evidence']], list(originals))
        self.assertEqual(finding['identifiers'], ['CVE-a', 'CVE-b', 'GHSA-same'])
        self.assertEqual(finding['source_tools'], ['osv', 'trivy'])
        self.assertEqual(finding['severity'], 'CRITICAL')
        self.assertTrue(finding['severity_conflict'])
        self.assertEqual([x['value'] for x in finding['fixed_version_candidates']], ['1.1.0', '2.0.0'])
        self.assertEqual(finding['review_status'], 'reported')
        self.assertEqual(r['summary']['raw_records'], 3)
        self.assertEqual(r['summary']['merged_pairs'], 0)
        self.assertEqual(r['deduplication']['before_finding_count'], 3)
        self.assertEqual(r['deduplication']['after_finding_count'], 1)
        self.assertEqual(r['deduplication']['removed_duplicate_count'], 2)

    def test_repeated_primary_with_same_ghsa_in_one_tool(self):
        f = self.fixture
        original = f.trivy_record()
        f.trivy['Results'][0]['Vulnerabilities'].append(deepcopy(original))
        r = f.run_normalize()
        self.assertEqual(len(r['findings']), 1)
        self.assertEqual(len(r['findings'][0]['evidence']), 2)
        self.assertEqual(r['summary']['merged_pairs'], 0)

    def test_multiple_installations_do_not_inflate_finding_count(self):
        self.duplicates()
        self.fixture.lock['packages']['node_modules/parent/node_modules/demo'] = {'version': '1.0.0'}
        r = self.fixture.run_normalize()
        self.assertEqual(len(r['findings']), 1)
        self.assertEqual(len(r['findings'][0]['package_ids']), 2)
        self.assertEqual(r['findings'][0]['dependency_types'], ['direct', 'indirect'])

    def test_different_primary_ghsas_sharing_cve_are_not_merged(self):
        f = self.fixture
        f.trivy_record(aid='CVE-shared', ghsa='GHSA-a')
        f.trivy_record(aid='CVE-shared', ghsa='GHSA-b')
        f.osv_record('GHSA-a', aliases=['CVE-shared'])
        f.osv_record('GHSA-b', aliases=['CVE-shared'])
        r = f.run_normalize()
        self.assertEqual(len(r['findings']), 2)
        self.assertEqual(r['summary']['merged_pairs'], 2)
        self.assertNotIn('deduplication', r)

    def test_multiple_ghsas_are_not_a_license_for_alias_merging(self):
        f = self.fixture
        f.osv_record('GHSA-a', aliases=['GHSA-b', 'CVE-shared'])
        f.osv_record('GHSA-b', aliases=['GHSA-a', 'CVE-shared'])
        r = f.run_normalize()
        self.assertEqual(len(r['findings']), 2)
        self.assertNotIn('deduplication', r)

    def test_cve_only_many_to_one_stays_ambiguous(self):
        f = self.fixture
        f.trivy_record(aid='CVE-common', VendorIDs=[])
        f.osv_record('GHSA-a', aliases=['CVE-common'])
        f.osv_record('GHSA-b', aliases=['CVE-common'])
        r = f.run_normalize()
        self.assertEqual(len(r['findings']), 3)
        self.assertEqual(r['summary']['manual_review'], 3)

    def test_nswg_manual_record_not_consolidated(self):
        f = self.fixture
        f.trivy_record(aid='NSWG-ECO-516', ghsa='GHSA-same')
        f.osv_record('GHSA-same', aliases=[])
        r = f.run_normalize()
        self.assertEqual(len(r['findings']), 2)
        self.assertIn('NSWG-ECO-516_requires_manual_review', r['findings'][0]['review_reasons'])

    def test_package_and_version_boundaries_preserved(self):
        f = self.fixture
        self.duplicates()
        item = f.osv['results'][0]['packages'][0]
        other_name, other_version = deepcopy(item), deepcopy(item)
        other_name['package']['name'] = 'other'
        other_version['package']['version'] = '2.0.0'
        f.osv['results'][0]['packages'].extend([other_name, other_version])
        r = f.run_normalize()
        self.assertEqual(len(r['findings']), 3)
        self.assertEqual(len(r['alias_groups']), 3)

    def test_failed_tool_is_not_used_as_identity_evidence(self):
        f = self.fixture
        self.duplicates()
        f.status['trivy'] = {'status': 'failed'}
        r = f.run_normalize()
        self.assertEqual(r['summary']['raw_records'], 1)
        self.assertEqual(r['findings'][0]['source_tools'], ['osv'])
        self.assertEqual(r['status'], 'partial')
        self.assertNotIn('deduplication', r)

    def test_unsupported_severity_survives_and_blocks_priority(self):
        a, _, _ = self.duplicates()
        a['Severity'] = 'INFO'
        r = self.fixture.run_normalize()
        finding = r['findings'][0]
        self.assertFalse(finding['priority_input_eligible'])
        self.assertIn('unsupported_severity_label', finding['review_reasons'])
        self.assertEqual(finding['severity_observations'][0]['raw'], 'INFO')

    def test_source_order_changes_do_not_change_identity_decision(self):
        self.duplicates()
        before = self.fixture.run_normalize()
        self.fixture.trivy['Results'][0]['Vulnerabilities'].reverse()
        after = self.fixture.run_normalize()
        self.assertEqual(before['summary'], after['summary'])
        self.assertEqual(before['findings'][0]['identifiers'], after['findings'][0]['identifiers'])

    def test_exactly_once_record_coverage_and_no_input_mutation(self):
        self.duplicates()
        before = deepcopy((self.fixture.trivy, self.fixture.osv))
        a, b = self.fixture.run_normalize(), self.fixture.run_normalize()
        self.assertEqual(a, b)
        self.assertEqual(before, (self.fixture.trivy, self.fixture.osv))
        evidence = [e for f in a['findings'] for e in f['evidence']]
        self.assertEqual(len(evidence), a['summary']['raw_records'])
        self.assertTrue(all(n == 1 for n in Counter(e['record_id'] for e in evidence).values()))
        for e in evidence:
            value = a['raw_results'][e['source_tool']]
            for part in e['json_pointer'].strip('/').split('/'):
                value = value[int(part)] if isinstance(value, list) else value[part]
            self.assertEqual(value, e['raw'])


if __name__ == '__main__':
    unittest.main()
