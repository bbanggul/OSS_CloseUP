import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

out=Path('/verification/results'); out.mkdir(parents=True,exist_ok=True)
for name,args in [
    ('worker-tests.txt',['-m','pytest','worker/tests','-q','-p','no:cacheprovider','--junitxml=/verification/results/worker-junit.xml']),
    ('service-run.txt',['/verification/verify_service.py']),
    ('http-run.txt',['/verification/verify_http.py'])]:
    with (out/name).open('w') as stream:
        result=subprocess.run([sys.executable,*args],stdout=stream,stderr=subprocess.STDOUT)
    print((out/name).read_text(),flush=True)
    result.check_returncode()
service=json.loads((out/'service-results.json').read_text())['records']
http=json.loads((out/'http-results.json').read_text())
summary={'cases':len({r['case_id'] for r in service}),'variants':len(service),
    'service_checks':sum(len(r['checks']) for r in service),
    'service_checks_passed':sum(c['passed'] for r in service for c in r['checks']),
    'http_checks':len(http['checks']),'http_checks_passed':sum(c['passed'] for c in http['checks']),
    'junit_suites':[e.attrib for e in ET.parse(out/'worker-junit.xml').getroot().iter('testsuite')]}
assert summary['cases']==29 and summary['variants']==38
assert all(r['passed'] for r in service) and http['passed']
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
source=Path('/source'); manifest={}
for folder in ('backend/app','worker/app','worker/tests','db','verification/package-api'):
    for p in sorted((source/folder).rglob('*')):
        if p.is_file() and not any(part in ('results','evidence','__pycache__') for part in p.parts):
            manifest[str(p.relative_to(source))]=hashlib.sha256(p.read_bytes()).hexdigest()
(out/'source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(summary,indent=2))
