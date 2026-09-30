"""Offline regression checks: all network probes are replaced with a fixture."""
import csv
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('segcheck.sh')
SCAN = '''# Nmap fixture
Nmap scan report for 10.20.30.40
Host is up.
PORT STATE SERVICE
443/tcp open https
Nmap done: 1 IP address (1 host up) scanned in 1.00 seconds
'''


class SegcheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='segcheck-tests-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.nc = self.bin / 'nc'
        self.nc.write_text('#!/bin/sh\nprintf \'%s\\n\' \'Connection succeeded, "quoted" <script>alert(1)</script>\'\n')
        self.nc.chmod(0o755)
        self.targets = self.root / 'targets with spaces.txt'
        self.targets.write_text('# comment\n\n10.20.30.0/24\n')
        self.scan = self.root / 'scan with spaces.nmap'
        self.scan.write_text(SCAN)
        self.output = self.root / 'results with spaces.csv'
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'])

    def run_tool(self, source='10.1.42.10', scans=None):
        result = subprocess.run(['bash', str(SCRIPT), '-f', '10.1.42.0/24', '-s', source,
                                 '-t', str(self.targets), '-o', str(self.output),
                                 *map(str, scans or [self.scan])],
                                capture_output=True, text=True, env=self.env)
        self.assertEqual(list(self.root.glob('.segcheck-*')), [])
        return result

    def rows(self):
        with self.output.open(newline='') as handle:
            return list(csv.reader(handle))

    def test_fail_subnet_paths_and_encoding(self):
        result = self.run_tool()
        self.assertEqual(result.returncode, 1, result.stderr)
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(len(row) == 7 for row in rows))
        self.assertEqual(rows[1][1:3], ['10.20.30.0/24', 'FAIL'])
        self.assertIn(', "quoted" <script>', rows[1][6])
        report = self.output.with_suffix('.html').read_text()
        self.assertIn('&lt;script&gt;', report)
        self.assertNotIn('<script>alert(1)</script>', report)
        self.assertIn('body.appendChild(row)', report)

    def test_exact_ip_precedes_subnet(self):
        self.targets.write_text('10.20.30.0/24\n10.20.30.40\n')
        self.assertEqual(self.run_tool().returncode, 1)
        self.assertEqual(self.rows()[1][1], '10.20.30.40')

    def test_outside_subnet_is_unknown(self):
        self.targets.write_text('10.20.31.0/24\n')
        self.assertEqual(self.run_tool().returncode, 1)
        self.assertEqual(self.rows()[1][1], 'Unknown')

    def test_refused_exit_zero(self):
        self.nc.write_text('#!/bin/sh\necho "Connection refused" >&2\nexit 1\n')
        self.assertEqual(self.run_tool().returncode, 0)
        self.assertEqual(self.rows()[1][2], 'PASS')

    def test_invalid_inputs(self):
        for content in ['', '<nmaprun></nmaprun>', SCAN.replace('Nmap done:', 'unfinished:'),
                        SCAN.replace('443/tcp', '99999/tcp')]:
            with self.subTest(content=content):
                self.scan.write_text(content)
                self.assertEqual(self.run_tool().returncode, 2)
                self.assertFalse(self.output.exists())

    def test_invalid_source(self):
        self.assertEqual(self.run_tool(source='999.1.1.1').returncode, 2)
        self.assertFalse(self.output.exists())

    def test_invalid_targets(self):
        for value in ['# only comment\n', '999.1.1.1', '10.20.0.0/99', 'bad hostname']:
            with self.subTest(value=value):
                self.targets.write_text(value)
                self.assertEqual(self.run_tool().returncode, 2)

    def test_missing_scan(self):
        self.assertEqual(self.run_tool(scans=[self.root / 'missing.nmap']).returncode, 2)

    def test_multiple_files_deduplicate(self):
        other = self.root / 'another scan.nmap'
        other.write_text(SCAN)
        self.assertEqual(self.run_tool(scans=[self.scan, other]).returncode, 1)
        self.assertEqual(len(self.rows()), 2)

    def test_execution_error_preserves_existing_report(self):
        self.output.write_text('existing report')
        self.nc.write_text('#!/bin/sh\necho "invalid option" >&2\nexit 1\n')
        self.assertEqual(self.run_tool().returncode, 2)
        self.assertEqual(self.output.read_text(), 'existing report')

    def test_valid_no_open_ports(self):
        self.scan.write_text(SCAN.replace('443/tcp open https', '443/tcp closed https'))
        self.assertEqual(self.run_tool().returncode, 0)
        self.assertEqual(self.rows()[1][6], 'No open ports detected')

    def test_output_cannot_overwrite_input(self):
        self.output = self.root / 'input.csv'
        self.output.write_text(SCAN)
        self.assertEqual(self.run_tool(scans=[self.output]).returncode, 2)
        self.assertEqual(self.output.read_text(), SCAN)

    def test_missing_dependency(self):
        self.nc.unlink()
        (self.bin / 'python3').symlink_to(sys.executable)
        self.env['PATH'] = str(self.bin)
        result = subprocess.run(['/bin/bash', str(SCRIPT), '-f', '10.1.42.0/24',
                                 '-s', '10.1.42.10', '-t', str(self.targets),
                                 '-o', str(self.output), str(self.scan)],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("'nc'", result.stderr)
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(shutil.which('node'), 'Node needed for JavaScript regression check')
    def test_html_sort_then_filter(self):
        self.assertEqual(self.run_tool().returncode, 1)
        report = self.output.with_suffix('.html').read_text()
        javascript = re.search(r'<script>(.*?)</script>', report, re.S).group(1)
        fixture = '''
const assert = require('node:assert/strict');
const rows = [
  {cells:[{textContent:'20'}],dataset:{status:'PASS'}},
  {cells:[{textContent:'3'}],dataset:{status:'FAIL'}}
];
const body = {rows, appendChild(row) {
  this.rows.splice(this.rows.indexOf(row), 1); this.rows.push(row);
}};
const table = {tBodies:[body], dataset:{}};
global.document = {
  getElementById() {return table;},
  querySelectorAll() {return body.rows;}
};
'''
        assertions = '''
filterRows('FAIL');
sortTable(0);
assert.deepEqual(body.rows.map(r => r.cells[0].textContent), ['3', '20']);
assert.deepEqual(body.rows.map(r => r.hidden), [false, true]);
filterRows('PASS');
assert.deepEqual(body.rows.map(r => r.hidden), [true, false]);
sortTable(0);
assert.deepEqual(body.rows.map(r => r.cells[0].textContent), ['20', '3']);
filterRows('ALL');
assert.ok(body.rows.every(r => !r.hidden));
'''
        result = subprocess.run(['node', '-e', fixture + javascript + assertions],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
