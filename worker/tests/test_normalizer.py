from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from app.normalizer import normalize_results, normalize_scan, packages_from_lock


class NormalizerTests(unittest.TestCase):
    def setUp(self):
        self.package = {'dependencies': {'demo': '1.0.0'}}
        self.lock = {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/demo': {'version': '1.0.0'}}}
        self.trivy = {'SchemaVersion': 2, 'Results': [{'Type': 'npm', 'Target': 'package-lock.json', 'Vulnerabilities': []}]}
        self.osv = {'results': [{'source': {'path': 'package-lock.json'}, 'packages': [
            {'package': {'ecosystem': 'npm', 'name': 'demo', 'version': '1.0.0'}, 'vulnerabilities': []}]}]}
        self.status = {t: {'status': 'completed'} for t in ('trivy', 'osv')}

    def trivy_record(self, aid='CVE-1', ghsa='GHSA-a', **extra):
        v = {'VulnerabilityID': aid, 'VendorIDs': [ghsa], 'PkgName': 'demo',
             'InstalledVersion': '1.0.0', 'Severity': 'HIGH', 'FixedVersion': '>=1.1.0, 2.0.0'}
        v.update(extra)
        self.trivy['Results'][0]['Vulnerabilities'].append(v)
        return v

    def osv_record(self, aid='GHSA-a', aliases=None, **extra):
        v = {'id': aid, 'aliases': ['CVE-1'] if aliases is None else aliases,
             'database_specific': {'severity': 'MODERATE'}, 'affected': []}
        v.update(extra)
        self.osv['results'][0]['packages'][0]['vulnerabilities'].append(v)
        return v

    def run_normalize(self):
        return normalize_results(self.package, self.lock, {'trivy': self.trivy, 'osv': self.osv},
                                 self.status, scan_id='scan-1')

    def test_direct_pair_preserves_ids_severity_and_raw_evidence(self):
        t = self.trivy_record()
        o = self.osv_record()
        result = self.run_normalize()
        f = result['findings'][0]
        self.assertEqual(result['summary']['merged_pairs'], 1)
        self.assertEqual(f['identifiers'], ['CVE-1', 'GHSA-a'])
        self.assertEqual(f['source_tools'], ['osv', 'trivy'])
        self.assertEqual([e['raw'] for e in f['evidence']], [t, o])
        self.assertEqual(f['severity_observations'][1]['normalized'], 'MEDIUM')
        self.assertEqual(f['severity_observations'][1]['raw'], 'MODERATE')
        self.assertTrue(f['severity_conflict'])
        self.assertEqual(f['severity'], 'HIGH')
        self.assertNotIn('priority', f)

    def test_shared_cve_does_not_collapse_distinct_ghsa_advisories(self):
        self.trivy_record(ghsa='GHSA-a')
        self.trivy_record(ghsa='GHSA-b')
        self.osv_record('GHSA-a')
        self.osv_record('GHSA-b')
        result = self.run_normalize()
        self.assertEqual(result['summary']['merged_pairs'], 2)
        self.assertEqual(len(result['findings']), 2)
        self.assertEqual(len(result['alias_groups']), 1)
        for f in result['findings']:
            self.assertEqual(len(f['evidence']), 2)
            self.assertEqual(f['review_status'], 'reported')

    def test_ambiguous_mapping_remains_unmerged(self):
        self.trivy_record(VendorIDs=[])
        self.osv_record('GHSA-a')
        self.osv_record('GHSA-b')
        r = self.run_normalize()
        self.assertEqual(r['summary']['merged_pairs'], 0)
        self.assertEqual(len(r['findings']), 3)
        self.assertEqual(r['summary']['manual_review'], 3)

    def test_distinct_ghsa_shared_cve_is_alias_only(self):
        self.trivy_record(ghsa='GHSA-a')
        self.osv_record('GHSA-b')
        r = self.run_normalize()
        self.assertEqual(r['summary']['merged_pairs'], 0)
        self.assertEqual(len(r['findings']), 2)
        self.assertEqual(len(r['alias_groups']), 1)

    def test_alias_transitive_chain_does_not_merge_findings(self):
        self.osv_record('GHSA-a', aliases=['CVE-left'])
        self.osv_record('GHSA-b', aliases=['CVE-left', 'CVE-right'])
        self.osv_record('GHSA-c', aliases=['CVE-right'])
        r = self.run_normalize()
        self.assertEqual(len(r['findings']), 3)
        self.assertEqual(len(r['alias_groups']), 1)
        self.assertEqual(r['summary']['merged_pairs'], 0)

    def test_shared_alias_cannot_cross_package_or_version(self):
        self.osv_record('GHSA-a', aliases=['CVE-shared'])
        template = deepcopy(self.osv['results'][0]['packages'][0])
        other_version = deepcopy(template)
        other_version['package']['version'] = '2.0.0'
        other_name = deepcopy(template)
        other_name['package']['name'] = 'other'
        self.osv['results'][0]['packages'].extend([other_version, other_name])
        r = self.run_normalize()
        self.assertEqual(len(r['alias_groups']), 3)
        self.assertEqual(len(r['findings']), 3)

    def test_record_order_does_not_change_semantic_pairing(self):
        self.trivy_record(ghsa='GHSA-a')
        self.trivy_record(ghsa='GHSA-b')
        self.osv_record('GHSA-a')
        self.osv_record('GHSA-b')
        def pairs(result):
            return sorted(tuple(sorted((e['source_tool'], e['raw'].get('id', e['raw'].get('VulnerabilityID')))
                                       for e in f['evidence'])) for f in result['findings'])
        before = self.run_normalize()
        self.osv['results'][0]['packages'][0]['vulnerabilities'].reverse()
        self.trivy['Results'][0]['Vulnerabilities'].reverse()
        after = self.run_normalize()
        self.assertEqual(pairs(before), pairs(after))
        self.assertEqual(before['summary'], after['summary'])

    def test_nswg_remains_manual_and_outside_alias_count(self):
        self.trivy_record(aid='NSWG-ECO-516', VendorIDs=[])
        r = self.run_normalize()
        self.assertEqual(r['summary']['manual_review'], 1)
        self.assertEqual(r['alias_groups'], [])
        self.assertNotIn('alias_group_id', r['findings'][0])

    def test_nested_same_version_links_all_paths_without_extra_findings(self):
        self.lock['packages']['node_modules/parent/node_modules/demo'] = {'version': '1.0.0'}
        self.trivy_record()
        r = self.run_normalize()
        f = r['findings'][0]
        self.assertEqual(len(f['package_ids']), 2)
        self.assertEqual(f['dependency_types'], ['direct', 'indirect'])
        self.assertEqual(f['package_mapping'], 'multiple_installations')
        self.assertEqual(len(r['findings']), 1)

    def test_version_mismatch_is_not_silently_linked(self):
        self.trivy_record(InstalledVersion='9.0.0')
        f = self.run_normalize()['findings'][0]
        self.assertEqual(f['package_ids'], [])
        self.assertIn('package_not_found_in_lock', f['review_reasons'])

    def test_fixes_only_from_matching_package_keep_range_context(self):
        v = self.osv_record(affected=[
            {'package': {'name': 'other', 'ecosystem': 'npm'}, 'ranges': [{'events': [{'fixed': '99'}]}]},
            {'package': {'name': 'demo', 'ecosystem': 'npm'}, 'ranges': [
                {'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '1.1.0'}]},
                {'type': 'SEMVER', 'events': [{'introduced': '2'}, {'fixed': '2.2.0'}]}]}])
        f = self.run_normalize()['findings'][0]
        self.assertEqual([c['value'] for c in f['fixed_version_candidates']], ['1.1.0', '2.2.0'])
        self.assertEqual(f['fixed_version_candidates'][0]['range'], v['affected'][1]['ranges'][0])
        self.assertNotIn('recommended_version', f)

    def test_unknown_severity_and_missing_fix_are_explicit(self):
        self.osv_record(database_specific={}, severity=[{'type': 'CVSS_V3', 'score': 'vector'}])
        f = self.run_normalize()['findings'][0]
        self.assertEqual(f['severity'], 'UNKNOWN')
        self.assertEqual(f['fix_information'], 'not_reported')
        self.assertEqual(f['evidence'][0]['raw']['severity'][0]['score'], 'vector')

    def test_failed_tool_payload_is_preserved_but_not_used(self):
        self.trivy_record()
        self.osv_record()
        self.status['trivy'] = {'status': 'failed', 'error': {'kind': 'timeout'}}
        r = self.run_normalize()
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['summary']['raw_records'], 1)
        self.assertEqual(r['findings'][0]['source_tools'], ['osv'])
        self.assertEqual(r['raw_results']['trivy'], self.trivy)

    def test_malformed_tool_is_transactionally_rejected(self):
        self.trivy_record()
        self.trivy['Results'][0]['Vulnerabilities'].append({'bad': 'record'})
        r = self.run_normalize()
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['findings'], [])
        self.assertEqual(r['tool_status']['trivy']['error']['kind'], 'normalization_error')

    def test_empty_invalid_trivy_container_is_not_clean(self):
        self.trivy['Results'] = {}
        self.assertEqual(self.run_normalize()['status'], 'partial')

    def test_both_failed_is_failed_not_clean_scan(self):
        self.status = {}
        r = self.run_normalize()
        self.assertEqual(r['status'], 'failed')
        self.assertEqual(r['findings'], [])

    def test_v1_scoped_and_nested_packages(self):
        lock = {'lockfileVersion': 1, 'dependencies': {'@scope/demo': {'version': '1', 'dependencies': {
            '@scope/demo': {'version': '2'}}}}}
        ps = packages_from_lock({'dependencies': {'@scope/demo': '1'}}, lock, 's')
        self.assertEqual([p['dependency_type'] for p in ps], ['direct', 'indirect'])
        self.assertEqual(ps[1]['lock_path'], 'node_modules/@scope/demo/node_modules/@scope/demo')

    def test_workspace_rejected_and_v2_supported(self):
        self.lock['lockfileVersion'] = 2
        self.assertEqual(len(self.run_normalize()['packages']), 1)
        self.package['workspaces'] = ['packages/*']
        with self.assertRaises(ValueError):
            self.run_normalize()

    def test_inputs_unchanged_and_identifiers_deterministic(self):
        self.trivy_record()
        original = deepcopy(self.trivy)
        a = self.run_normalize()
        b = self.run_normalize()
        self.assertEqual(a, b)
        self.assertEqual(self.trivy, original)
        a['findings'][0]['evidence'][0]['raw']['Severity'] = 'LOW'
        self.assertEqual(self.trivy, original)

    def test_portable_scan_directory_and_hash_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'inputs').mkdir()
            manifest = {'attempt_id': 'a', 'tools': self.status, 'inputs': {}}
            for name, data in (('package.json', self.package), ('package-lock.json', self.lock)):
                content = json.dumps(data).encode()
                (root / 'inputs' / name).write_bytes(content)
                manifest['inputs'][name] = {'sha256': hashlib.sha256(content).hexdigest(),
                                            'snapshot_path': '/inaccessible/container/path'}
            (root / 'manifest.json').write_text(json.dumps(manifest))
            (root / 'trivy.json').write_text(json.dumps(self.trivy))
            (root / 'osv.json').write_text(json.dumps(self.osv))
            self.assertEqual(normalize_scan(root)['status'], 'completed')
            (root / 'inputs' / 'package.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                normalize_scan(root)


    def test_unsupported_labels_are_preserved_and_not_priority_eligible(self):
        for label in ('INFO', 'UNRECOGNIZED', 3):
            with self.subTest(label=label):
                self.setUp()
                raw = self.trivy_record(Severity=label)
                result = self.run_normalize()
                f = result['findings'][0]
                self.assertEqual(f['severity'], 'UNKNOWN')
                self.assertFalse(f['priority_input_eligible'])
                self.assertIn('unsupported_severity_label', f['review_reasons'])
                self.assertEqual(f['severity_observations'][0]['raw'], label)
                self.assertEqual(f['evidence'][0]['raw'], raw)
                self.assertEqual(result['raw_results']['trivy'], self.trivy)

    def test_missing_and_unknown_are_eligible_without_inventing_conflict(self):
        for label in (None, '', 'UNKNOWN'):
            self.setUp()
            self.trivy_record(Severity=label)
            self.osv_record(database_specific={'severity': 'HIGH'})
            f = self.run_normalize()['findings'][0]
            self.assertEqual(f['severity'], 'HIGH')
            self.assertFalse(f['severity_conflict'])
            self.assertTrue(f['priority_input_eligible'])
            self.assertEqual(f['severity_observations'][0]['raw'], label)

    def test_same_grade_without_identifier_evidence_is_not_merged(self):
        self.trivy_record(aid='CVE-unrelated', VendorIDs=[])
        self.osv_record(aid='GHSA-unrelated', aliases=[], database_specific={'severity': 'HIGH'})
        result = self.run_normalize()
        self.assertEqual(len(result['findings']), 2)
        self.assertEqual(result['summary']['merged_pairs'], 0)

    def test_recorded_nswg_raw_retains_manual_review_and_constraint(self):
        path = Path(__file__).parent / 'fixtures' / 'nswg-eco-516.json'
        fixture = json.loads(path.read_text())
        raw = fixture['raw_record']
        self.package = {'dependencies': {'lodash': '4.17.15'}}
        self.lock = {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/lodash': {'version': '4.17.15'}}}
        self.trivy['Results'][0]['Vulnerabilities'] = [raw]
        f = self.run_normalize()['findings'][0]
        self.assertEqual(f['evidence'][0]['raw'], raw)
        self.assertIn('NSWG-ECO-516_requires_manual_review', f['review_reasons'])
        self.assertEqual(f['review_status'], 'needs_review')
        self.assertEqual(f['fixed_version_candidates'][0]['raw'], '>=4.17.19')
        self.assertNotIn('recommended_fixed_version', f)


if __name__ == '__main__':
    unittest.main()
