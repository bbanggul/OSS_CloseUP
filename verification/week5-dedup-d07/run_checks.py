"""Run the portable review suite; nonzero exit on test or evidence failure."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

root = Path('/verification')
out = root / 'results'
out.mkdir(parents=True, exist_ok=True)
for name, args in [
    ('worker-tests.txt', ['-m', 'pytest', 'worker/tests', '-q', '-p', 'no:cacheprovider',
                          '--junitxml=/verification/results/worker-junit.xml']),
    ('service-run.txt', ['/verification/verify_service.py']),
    ('d07-run.txt', ['/verification/verify_boundaries.py']),
]:
    with (out / name).open('w') as stream:
        result = subprocess.run([sys.executable, *args], stdout=stream, stderr=subprocess.STDOUT)
    print((out / name).read_text(), flush=True)
    result.check_returncode()
service = json.loads((out / 'service-results.json').read_text())['records']
d07 = json.loads((out / 'd07-results.json').read_text())
order = json.loads((out / 'cross-case-order.json').read_text())
summary = {'original_cases': len({r['case_id'] for r in service}),
           'variants': len(service), 'variants_passed': sum(r['passed'] for r in service),
           'd07_scenarios': len(d07), 'd07_scenarios_passed': sum(r['passed'] for r in d07)}
for key, rows in [('service', service), ('d07', d07), ('ordering', [order])]:
    checks = [c for row in rows for c in row['checks']]
    summary[key + '_checks'] = len(checks)
    summary[key + '_checks_passed'] = sum(c['passed'] for c in checks)
    assert all(c['passed'] for c in checks), key
summary['junit_suites'] = [e.attrib for e in ET.parse(out / 'worker-junit.xml').getroot().iter('testsuite')]
summary['d07_diagnostics'] = [{k: r[k] for k in ('scenario', 'contract_diagnostics')} for r in d07]
assert summary['original_cases'] == 29 and summary['variants'] == 38
assert len(d07) == 8
(out / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
manifest = {'base_commit': '6c122e5329c2104ddc2da2195bc688332358e6b9', 'files': {}}
source = Path('/source')
for folder in ['backend/app', 'worker/app', 'worker/tests', 'db', 'verification/week5-dedup-d07']:
    for path in sorted((source / folder).rglob('*')):
        if not path.is_file() or any(p in ('results', 'evidence', '__pycache__') for p in path.parts):
            continue
        manifest['files'][str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
case_path = source / 'docs/priority-engine/accepted-cases.json'
manifest['files'][str(case_path.relative_to(source))] = hashlib.sha256(case_path.read_bytes()).hexdigest()
(out / 'source-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(summary, ensure_ascii=False, indent=2))
