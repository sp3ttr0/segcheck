#!/bin/bash

# ===============================================================
# segcheck.sh - Network Segmentation Validation Tool
# ---------------------------------------------------------------
# Author: Howell King Jr. | Github: https://github.com/sp3ttr0
# ===============================================================

# Python's standard library handles validation, CIDR matching and report encoding.
if ! command -v python3 >/dev/null 2>&1; then
    printf 'Error: python3 is required.\n' >&2
    exit 2
fi
exec python3 - "$@" <<'PYTHON'
import argparse
import csv
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile


class InputError(Exception):
    pass


def ipv4(value):
    try:
        return ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise InputError(f"Invalid IPv4 address: {value!r}")


def subnet(value):
    if '/' not in value:
        raise InputError(f"Subnet must include a CIDR prefix: {value!r}")
    try:
        return ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        raise InputError(f"Invalid IPv4 subnet: {value!r}")


def read_text(path):
    try:
        if not path.is_file():
            raise InputError(f"Input is not a regular file: {path}")
        return path.read_text(encoding='utf-8-sig')
    except (OSError, UnicodeError) as exc:
        raise InputError(f"Cannot read {path}: {exc}")


def load_targets(path):
    targets = []
    seen = set()
    for number, line in enumerate(read_text(path).splitlines(), 1):
        value = line.split('#', 1)[0].strip()
        if not value or value in seen:
            continue
        seen.add(value)
        try:
            if '/' in value:
                targets.append((value, 'subnet', subnet(value)))
            elif re.fullmatch(r'[0-9.]+', value):
                targets.append((value, 'ip', ipv4(value)))
            else:
                name = value.rstrip('.')
                labels = name.split('.')
                if len(name) > 253 or any(not re.fullmatch(
                        r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                        for label in labels):
                    raise InputError(f"Invalid hostname: {value!r}")
                try:
                    addresses = {ipv4(item[4][0]) for item in socket.getaddrinfo(
                        value, None, socket.AF_INET, socket.SOCK_STREAM)}
                except socket.gaierror as exc:
                    raise InputError(f"Cannot resolve hostname {value!r}: {exc}")
                if not addresses:
                    raise InputError(f"Hostname has no IPv4 addresses: {value!r}")
                targets.append((value, 'hostname', addresses))
        except InputError as exc:
            raise InputError(f"{path}:{number}: {exc}")
    if not targets:
        raise InputError(f"Target file has no targets: {path}")
    return targets


def load_scans(paths):
    entries = set()
    for path in paths:
        content = read_text(path)
        # Require normal-text output with a completion footer and a host report.
        # This prevents missing, empty, truncated, XML or arbitrary inputs passing.
        if not re.search(r'^Nmap done:', content, re.M):
            raise InputError(f"Missing Nmap completion footer in {path}; use complete -oN output")
        address = None
        host_count = 0
        for number, line in enumerate(content.splitlines(), 1):
            if line.startswith('Nmap scan report for '):
                token = line.rsplit(None, 1)[-1].strip('()')
                try:
                    address = ipv4(token)
                except InputError as exc:
                    raise InputError(f"{path}:{number}: {exc}")
                host_count += 1
            elif re.match(r'^\s*\d+/(?:tcp|udp)\b', line):
                fields = line.split()
                if address is None or len(fields) < 3:
                    raise InputError(f"Malformed port row at {path}:{number}")
                port_text, protocol = fields[0].split('/')
                port = int(port_text)
                if not 1 <= port <= 65535:
                    raise InputError(f"Invalid port at {path}:{number}: {port}")
                if fields[1] not in {'open', 'closed', 'filtered', 'unfiltered',
                                     'open|filtered', 'closed|filtered'}:
                    raise InputError(f"Invalid port state at {path}:{number}: {fields[1]}")
                # Preserve the original inclusion of open|filtered rows.
                if 'open' in fields[1]:
                    entries.add((address, port, protocol, fields[2]))
        if not host_count:
            raise InputError(f"No IPv4 host reports in {path}; no test evidence available")
    return sorted(entries, key=lambda item: (int(item[0]), *item[1:]))


def find_traffic_to(address, targets):
    for kind in ('ip', 'subnet', 'hostname'):
        for label, target_kind, value in targets:
            if target_kind != kind:
                continue
            if (kind == 'ip' and address == value) or (
                    kind != 'ip' and address in value):
                return label
    return 'Unknown'


def detect_source():
    if shutil.which('ip') is None:
        raise InputError("'ip' is required for source detection; supply -s explicitly instead")
    result = subprocess.run(['ip', '-j', '-4', 'addr', 'show'], capture_output=True, text=True)
    if result.returncode:
        raise InputError(f"Source detection failed: {result.stderr.strip()}")
    try:
        for interface in json.loads(result.stdout):
            for info in interface.get('addr_info', []):
                address = ipv4(info['local'])
                if not address.is_loopback:
                    return address
    except (ValueError, KeyError, TypeError) as exc:
        raise InputError(f"Cannot parse source detection output: {exc}")
    raise InputError('Unable to determine a non-loopback source IP; supply -s')


def probe(address, port, protocol):
    command = ['nc', '-zvv', str(address), str(port)]
    if protocol == 'udp':
        command = ['nc', '-uzvv', str(address), str(port), '-w', '1']
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors='replace')
    output = result.stdout.strip()
    # Netcat normally uses 0 for success and 1 for a failed connection.
    # Treat unsupported flags and other invocation errors as execution errors.
    if result.returncode not in (0, 1) or re.search(
            r'usage:|invalid option|illegal option|unrecognized option|not supported|'
            r'permission denied|operation not permitted|invalid argument', output, re.I):
        raise InputError(f"Netcat execution failed for {address}:{port}/{protocol}: {output}")
    return output


HEADERS = ['Traffic From', 'Traffic To', 'Status', 'Source IP',
           'Destination IP', 'Open Ports', 'Notes']


def render_html(rows):
    counts = {status: sum(row[2] == status for row in rows) for status in ('PASS', 'FAIL')}
    document = '''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>segcheck results</title>
<style>
body{font-family:Arial,sans-serif;background:#f4f6f8;padding:24px}
table{border-collapse:collapse;width:100%;background:white}
th,td{border:1px solid #ddd;padding:10px;text-align:left}
th{background:#c9d7ef;cursor:pointer}td:last-child{white-space:pre-wrap;overflow-wrap:anywhere}
tbody tr:nth-child(even){background:#eef3fb}.PASS{color:#1e8449}.FAIL{color:#c0392b}
button{padding:8px 14px;margin:8px 8px 16px 0;cursor:pointer}
</style></head><body><h1>segcheck</h1><h2>Network Segmentation Validation Tool</h2>
<p>Network Segmentation Test Netcat Results</p>
'''
    document += f'<p>PASS: {counts["PASS"]} &nbsp; FAIL: {counts["FAIL"]} &nbsp; Total: {len(rows)}</p>\n'
    for status, label in [('ALL', 'Show All'), ('PASS', 'PASS Only'), ('FAIL', 'FAIL Only')]:
        document += f'<button onclick="filterRows(\'{status}\')">{label}</button>'
    document += '<table id="resultTable"><thead><tr>'
    document += ''.join(f'<th onclick="sortTable({n})">{html.escape(name)}</th>'
                        for n, name in enumerate(HEADERS))
    document += '</tr></thead><tbody>\n'
    for row in rows:
        document += f'<tr data-status="{row[2]}">'
        document += ''.join(f'<td>{html.escape(str(value), quote=True)}</td>' for value in row)
        document += '</tr>\n'
    return document + '''</tbody></table>
<script>
function filterRows(type) {
  document.querySelectorAll('#resultTable tbody tr').forEach(row => {
    row.hidden = type !== 'ALL' && row.dataset.status !== type;
  });
}
function sortTable(column) {
  const table = document.getElementById('resultTable');
  const body = table.tBodies[0];
  const ascending = table.dataset.column !== String(column) || table.dataset.direction !== 'asc';
  table.dataset.column = String(column);
  table.dataset.direction = ascending ? 'asc' : 'desc';
  Array.from(body.rows).sort((a, b) => {
    const order = a.cells[column].textContent.localeCompare(b.cells[column].textContent, undefined, {numeric:true});
    return ascending ? order : -order;
  }).forEach(row => body.appendChild(row));
}
</script></body></html>
'''


def main():
    parser = argparse.ArgumentParser(description='Validate segmentation using existing Nmap normal-text output.',
        epilog='Exit codes: 0 = no FAIL results, 1 = FAIL found, 2 = input/execution error. '
               '-f and -s are report labels; they do not bind network traffic.')
    parser.add_argument('-f', required=True, help='Traffic From IPv4 subnet in CIDR notation')
    parser.add_argument('-s', help='Source IPv4 report label (otherwise detected using ip)')
    parser.add_argument('-t', required=True, type=Path, help='Target file')
    parser.add_argument('-o', required=True, type=Path, help='CSV output path ending in .csv')
    parser.add_argument('scans', nargs='+', type=Path, help='Complete Nmap -oN output files')
    args = parser.parse_args()
    if shutil.which('nc') is None:
        raise InputError("Required dependency 'nc' was not found")
    subnet(args.f)
    source = ipv4(args.s) if args.s is not None else detect_source()
    targets = load_targets(args.t)
    entries = load_scans(args.scans)
    if args.o.suffix != '.csv':
        raise InputError('Output filename must end in .csv')
    destinations = [args.o.absolute(), args.o.with_suffix('.html').absolute()]
    inputs = {path.resolve() for path in [args.t, *args.scans]}
    for path in destinations:
        if path.resolve() in inputs:
            raise InputError(f"Output would overwrite an input: {path}")
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise InputError(f"Output must be a regular file, not a symlink or directory: {path}")
        if not path.parent.is_dir():
            raise InputError(f"Output directory does not exist: {path.parent}")

    # Stage both reports in the destination directory. Context cleanup also runs
    # on validation/probe/write errors and Ctrl-C; no persistent temp files.
    with tempfile.TemporaryDirectory(prefix='.segcheck-', dir=destinations[0].parent) as temporary:
        rows = []
        if not entries:
            for label, _, _ in targets:
                rows.append([args.f, label, 'PASS', str(source), 'N/A', 'N/A', 'No open ports detected'])
        for address, port, protocol, service in entries:
            first = probe(address, port, protocol)
            second = probe(address, port, protocol)
            status = 'FAIL' if re.search(r'open|succeeded', second, re.I) else 'PASS'
            rows.append([args.f, find_traffic_to(address, targets), status, str(source),
                         str(address), f'{port}/{protocol}',
                         f'Run1: {first}\nRun2: {second} ({protocol.upper()})'])
        staged_csv = Path(temporary) / 'report.csv'
        staged_html = Path(temporary) / 'report.html'
        with staged_csv.open('w', encoding='utf-8', newline='') as handle:
            writer = csv.writer(handle)
            writer.writerow(HEADERS)
            writer.writerows(rows)
        staged_html.write_text(render_html(rows), encoding='utf-8')
        os.replace(staged_csv, destinations[0])
        os.replace(staged_html, destinations[1])

    print('segcheck - Network Segmentation Validation Tool\n')
    print('\t'.join(HEADERS))
    for row in rows:
        print('\t'.join(str(value).replace('\n', ' | ') for value in row))
    failures = sum(row[2] == 'FAIL' for row in rows)
    print(f'\nPASS: {len(rows) - failures}  FAIL: {failures}  Total: {len(rows)}')
    if not failures:
        print('Segmentation Pass')
    print(f'Results saved to {destinations[0]} and {destinations[1]}')
    return 1 if failures else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (InputError, OSError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print('\nInterrupted; incomplete reports were not published.', file=sys.stderr)
        sys.exit(2)
PYTHON
