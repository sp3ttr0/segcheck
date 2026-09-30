# segcheck

**segcheck** is a lightweight tool with a Bash entry point and Python 3 standard-library implementation for checking network segmentation using existing Nmap scan results and Netcat verification.

It parses Nmap normal-text output, tests each discovered destination/port entry twice using Netcat, and generates:

- 📄 CSV report with properly quoted fields.
- 🌐 Interactive HTML report with sortable columns and PASS/FAIL filters.
- 🖥️ Terminal output with both connection attempts and a results summary.

Author: Howell King Jr. | [GitHub: sp3ttr0](https://github.com/sp3ttr0)

## 📂 Output Example

Illustrative terminal results, with spacing adjusted for readability and Netcat messages shortened:

```text
segcheck - Network Segmentation Validation Tool

Traffic From  Traffic To   Status  Source IP   Destination IP  Open Ports  Notes
10.1.42.0/24   10.1.50.10   PASS    10.1.42.5   10.1.50.10      443/tcp     Run1: refused | Run2: refused (TCP)
10.1.42.0/24   10.1.60.20   FAIL    10.1.42.5   10.1.60.20      22/tcp      Run1: succeeded | Run2: succeeded (TCP)

PASS: 1  FAIL: 1  Total: 2
```

Using `-o results.csv` produces `results.csv` and `results.html`. Existing reports are replaced on completion. Terminal output is currently plain text.

## ⚙️ Requirements

| Dependency | Purpose |
| --- | --- |
| Bash | Runs the script entry point. |
| Python 3 | Validation, parsing, hostname resolution, CIDR matching, and report generation. No third-party packages required. |
| Netcat (`nc`) | Connectivity checks; must support `-zvv` and `-uzvv`. |
| Linux `ip` with JSON output support | Automatic source-IP detection when `-s` is omitted. |
| Nmap | Produces the input scan files; not invoked by segcheck or required on the machine processing existing files. |

`ipcalc` and `dig` are no longer required. On machines without Linux `ip`, supply `-s` explicitly.

## 📥 Installation

```bash
git clone https://github.com/sp3ttr0/segcheck.git
cd segcheck
chmod +x segcheck.sh
```

Use the revised `segcheck.sh` from this workspace if it has not yet been published to the repository above.

## 🧪 Usage

```bash
./segcheck.sh -f <traffic_from_subnet> [-s <source_ip>] \
  -t <targets_file> -o <output.csv> <nmap_output_files...>
```

Example with multiple scan files, including a filename containing spaces:

```bash
./segcheck.sh -f 10.1.42.0/24 -s 10.1.42.5 \
  -t targets.txt -o results.csv 'scan one.nmap' scan2.nmap
```

You can also run `bash segcheck.sh` without setting executable permissions.

## 📌 Arguments

| Option | Description |
| --- | --- |
| `-f` | Required IPv4 source subnet in CIDR notation, used as the “Traffic From” label. |
| `-s` | Optional IPv4 source label. Otherwise detected using Linux `ip`. |
| `-t` | Required targets file containing IPv4 addresses, subnets, or resolvable hostnames. |
| `-o` | Required output path ending in `.csv`; a sibling `.html` report is generated. The parent directory must exist. |
| Positional files | One or more complete Nmap normal-text (`-oN`) output files. |
| `-h`, `--help` | Show usage information. |

`-f` and `-s` label the report; they do not bind connections to a source address or configure routing.

## 🎯 Targets and Scan Files

Example `targets.txt`:

```text
# One target per line
10.1.50.10
10.1.60.0/24
server.example.com
```

Blank lines and `#` comments are ignored. Hostnames must resolve to IPv4 addresses. All returned IPv4 addresses are considered when assigning labels. Exact IP matches take priority over subnet matches, then hostname matches. The first matching subnet in the file wins.

The targets file assigns “Traffic To” labels; it does not restrict which destinations are probed. Unmatched destinations from the scan files are still tested and labeled `Unknown`.

Each scan file must contain an IPv4 host report and an `Nmap done:` completion footer. Empty, incomplete, XML, grepable, and zero-host inputs are rejected before probing. Duplicate destination/port/protocol/service entries across files are combined. Entries marked `open|filtered` remain included alongside `open` entries.

## 📊 Result Interpretation

The current verdict rules assume tested connections should be blocked:

- Both Netcat attempts are recorded, but only the second attempt determines the verdict.
- A second-attempt message containing `open` or `succeeded` produces **FAIL**.
- Other connection outcomes, including refusal, produce **PASS** unless identified as an execution error.
- Valid scans with no extracted open ports generate PASS rows without Netcat probes.

A PASS or exit code `0` does not independently prove segmentation. UDP output retains Netcat’s limitations, and TCP probes currently have no explicit timeout.

## 🚦 Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | No FAIL rows under the current verdict rules. |
| `1` | At least one FAIL row. |
| `2` | Invalid input, missing dependency, execution/write error, or Ctrl-C interruption. |

## 🧹 Report Handling

CSV fields are quoted using standard CSV encoding, including embedded quotes and newlines; every row has seven columns. HTML values are escaped, and sorting preserves filtering.

Reports are staged in a temporary directory that is cleaned up on normal completion, exceptions, and Ctrl-C. Each output replacement is atomic individually; the CSV/HTML pair is not atomic, so a write error during the second replacement can leave the CSV newer than the HTML.

## ✅ Offline Checks

```bash
python3 -B test_segcheck.py
```

Tests replace Netcat with local fixtures and do not probe network targets. The JavaScript sorting/filtering check runs when Node.js is available.
