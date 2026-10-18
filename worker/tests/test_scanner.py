import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from app.scanner import run_scan


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root / "package.json"
        self.lock = self.root / "package-lock.json"
        self.package.write_text('{"name":"test"}')
        self.lock.write_text('{"lockfileVersion":3,"packages":{}}')
        self.output = self.root / "results"

    def binary(self, name, *, code=0, data=None, delay=0, raw=None):
        path = self.root / name
        payload = json.dumps(data) if raw is None else raw
        path.write_text(
            f"#!{sys.executable}\n"
            "import sys, time\nfrom pathlib import Path\n"
            "if '--version' in sys.argv:\n print('Version: test-1'); sys.exit(0)\n"
            f"time.sleep({delay!r})\n"
            "flag = '--output' if '--output' in sys.argv else '--output-file'\n"
            f"Path(sys.argv[sys.argv.index(flag)+1]).write_text({payload!r})\n"
            "print('scanner log', file=sys.stderr)\n"
            f"sys.exit({code})\n"
        )
        path.chmod(0o755)
        return str(path)

    def run_pair(self, trivy=None, osv=None, timeout=2):
        return run_scan(self.package, self.lock, self.output, timeout_seconds=timeout,
                        trivy_binary=trivy or self.binary('trivy', data={'SchemaVersion': 2}),
                        osv_binary=osv or self.binary('osv', data={'results': []}))

    def test_osv_findings_exit_one_is_success_and_evidence_preserved(self):
        data = {'results': [{'packages': [{'vulnerabilities': [{'id': 'TEST-1'}]}]}]}
        report = self.run_pair(osv=self.binary('osv', code=1, data=data))
        self.assertEqual(report['status'], 'completed')
        tool = report['tools']['osv']
        self.assertEqual(tool['exit_code'], 1)
        self.assertEqual(json.loads(Path(tool['raw_output_path']).read_text()), data)
        self.assertIn('test-1', tool['version']['text'])
        self.assertIn('scanner log', Path(tool['stderr_path']).read_text())
        self.assertEqual(json.loads(Path(report['manifest_path']).read_text()), report)
        self.assertEqual(Path(report['inputs']['package.json']['snapshot_path']).read_bytes(),
                         self.package.read_bytes())

    def test_tool_failure_does_not_prevent_other_tool(self):
        report = self.run_pair(trivy=self.binary('trivy', code=2, data={}))
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['tools']['trivy']['error']['kind'], 'tool_error')
        self.assertEqual(report['tools']['osv']['status'], 'completed')

    def test_missing_binaries_fail_without_clean_result(self):
        missing = str(self.root / 'missing')
        report = self.run_pair(trivy=missing, osv=missing)
        self.assertEqual(report['status'], 'failed')
        self.assertIsNone(report['tools']['osv']['exit_code'])
        self.assertEqual(report['tools']['osv']['error']['kind'], 'launch_error')

    def test_timeout_is_recorded_and_other_tool_runs(self):
        # Allow interpreter startup on a busy host; the delayed tool still exceeds
        # the deadline. This checks isolation of the timeout, not startup speed.
        report = self.run_pair(trivy=self.binary('trivy', delay=5), timeout=2)
        self.assertEqual(report['status'], 'partial')
        self.assertTrue(report['tools']['trivy']['timed_out'])
        self.assertEqual(report['tools']['osv']['status'], 'completed')
        self.assertLess(report['tools']['trivy']['duration_seconds'], 4)

    def test_invalid_output_rejected_even_with_success_exit(self):
        for raw in ('', '{', '{}', '[]'):
            with self.subTest(raw=raw):
                report = self.run_pair(osv=self.binary('osv', code=1, raw=raw))
                self.assertEqual(report['tools']['osv']['error']['kind'], 'invalid_output')

    def test_clean_results_are_completed(self):
        self.assertEqual(self.run_pair()['status'], 'completed')

    def test_attempts_do_not_overwrite_prior_evidence(self):
        first = self.run_pair()
        original = Path(first['manifest_path']).read_bytes()
        second = self.run_pair()
        self.assertNotEqual(first['attempt_id'], second['attempt_id'])
        self.assertEqual(Path(first['manifest_path']).read_bytes(), original)

    def test_invalid_input_rejected_before_creating_output(self):
        for content in ('broken', '[]', '{}', '{"lockfileVersion":3}'):
            self.lock.write_text(content)
            with self.subTest(content=content), self.assertRaises(ValueError):
                self.run_pair()
        self.assertFalse(self.output.exists())

    def test_missing_input_and_invalid_timeout(self):
        for timeout in (0, -1, float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                self.run_pair(timeout=timeout)
        self.package.unlink()
        with self.assertRaises(ValueError):
            self.run_pair()

    def test_timeout_kills_child_process(self):
        marker = self.root / 'child-survived'
        binary = self.root / 'forking-tool'
        binary.write_text(
            f'#!{sys.executable}\n'
            'import subprocess, sys, time\n'
            "if '--version' in sys.argv:\n print('test'); sys.exit(0)\n"
            f'child = "import time; from pathlib import Path; time.sleep(1); Path({str(marker)!r}).touch()"\n'
            'subprocess.Popen([sys.executable, "-c", child])\n'
            'time.sleep(5)\n'
        )
        binary.chmod(0o755)
        self.run_pair(trivy=str(binary), timeout=0.3)
        import time
        time.sleep(1.1)
        self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
