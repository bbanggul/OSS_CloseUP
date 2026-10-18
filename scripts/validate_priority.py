#!/usr/bin/env python3
"""Run synthetic priority tests and save reproducible evidence (standard library)."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import platform
import subprocess
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed_ids = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed_ids.append(test.id())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--include-regression', action='store_true',
                        help='Also run the existing scanner and normalizer tests')
    parser.add_argument('--output-dir', type=Path,
                        default=ROOT / 'docs' / 'priority-engine' / 'validation-v0.3')
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / 'worker'))
    patterns = ['test_priority*.py', 'test_review_policy.py', 'test_accepted_cases.py']
    if args.include_regression:
        patterns += ['test_normalizer.py', 'test_scanner.py']
    suite = unittest.TestSuite(unittest.defaultTestLoader.discover(
        str(ROOT / 'worker' / 'tests'), pattern=pattern) for pattern in patterns)
    stream = io.StringIO()
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.perf_counter()
    result = unittest.TextTestRunner(stream=stream, verbosity=2,
                                     resultclass=RecordedResult).run(suite)
    elapsed = time.perf_counter() - started
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / 'unittest.txt').write_text(stream.getvalue(), encoding='utf-8')

    from app.priority import calculate_priorities
    fixtures = ROOT / 'docs' / 'priority-engine'
    sample = json.loads((fixtures / 'example-input.json').read_text(encoding='utf-8'))
    actual = calculate_priorities(sample, allow_test_data=True)
    expected = json.loads((fixtures / 'example-expected.json').read_text(encoding='utf-8'))
    (output / 'example-actual.json').write_text(
        json.dumps(actual, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    names = ['worker/app/priority.py', 'worker/tests/test_priority.py',
             'scripts/validate_priority.py', 'docs/priority-engine/example-input.json',
             'docs/priority-engine/example-expected.json', 'worker/app/review_policy.py',
             'worker/app/normalizer.py', 'worker/tests/test_priority_review.py',
             'worker/tests/test_review_policy.py', 'worker/tests/test_accepted_cases.py',
             'worker/tests/fixtures/nswg-eco-516.json', 'docs/priority-engine/accepted-cases.json',
             'docs/priority-engine/contract-v0.2.md', 'docs/priority-engine/contract-v0.3.md',
             'docs/priority-engine/README.md', 'worker/app/priority_stage.py',
             'worker/tests/test_priority_stage.py', 'docs/priority-engine/INTEGRATION.md']
    if args.include_regression:
        names += ['worker/app/normalizer.py', 'worker/app/scanner.py',
                  'worker/tests/test_normalizer.py', 'worker/tests/test_scanner.py']
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names}
    revision = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                              capture_output=True, text=True)
    report = {
        'schema_version': 'priority-validation-v1',
        'started_at_utc': started_at,
        'elapsed_seconds': round(elapsed, 3),
        'python': platform.python_version(), 'platform': platform.platform(),
        'source_base_commit': revision.stdout.strip() if revision.returncode == 0 else None,
        'source_note': 'Working files are identified by SHA-256, not by the baseline commit.',
        'contract': 'priority-io-v2 / priority-v1 / activity-facts-v1 / license-review-v1; D01-D07 accepted; priority-stage-v1 persistence boundary',
        'command': ['python3', 'scripts/validate_priority.py'] +
                   (['--include-regression'] if args.include_regression else []),
        'output_dir': str(output.relative_to(ROOT)) if output.is_relative_to(ROOT) else str(output),
        'success': result.wasSuccessful() and actual == expected,
        'tests_run': result.testsRun,
        'passed_test_methods': len(result.passed_ids),
        'passed_by_module': dict(Counter(name.split('.')[0] for name in result.passed_ids)),
        'failures': [{'test': str(test), 'traceback': trace} for test, trace in result.failures],
        'errors': [{'test': str(test), 'traceback': trace} for test, trace in result.errors],
        'skipped': [{'test': str(test), 'reason': reason} for test, reason in result.skipped],
        'passed_test_ids': result.passed_ids,
        'contract_example_exact_match': actual == expected,
        'source_sha256': hashes,
        'scope': 'Pure-function rules, 29 module cases and D07 on-disk SQLite transaction tests; optional scanner/normalizer regression.',
        'not_validated': [
            'Changes to upstream after the recorded source_base_commit',
            'Production PostgreSQL adapter, worker integration, same-scan membership, fencing and migrations',
            'API/UI display including global unique UNKNOWN count and scan-level zero results',
            'Live scanners, vulnerability databases, actual API models and human evaluation',
            'Production DB/API/UI acceptance of all 29 cases and D07 persistence boundary',
        ],
    }
    (output / 'results.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: report[key] for key in (
        'success', 'tests_run', 'passed_by_module', 'contract_example_exact_match', 'output_dir')},
        ensure_ascii=False, indent=2))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
