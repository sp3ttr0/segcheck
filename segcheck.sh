#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to display usage information
usage() {
    echo "Usage: $0 -f <traffic_from_subnet> -t <targets_file> -o <output_file> <nmap_output_file1> [<nmap_output_file2> ...]"
    echo
    echo "  -f   Subnet defining the Traffic From (e.g., 10.1.42.0/24)"
    echo "  -t   File containing targets (IPs, hostnames, or subnets)"
    echo "  -o   Output CSV and HTML file"
    exit 1
}

# Parse options
while getopts ":f:t:o:" opt; do
    case ${opt} in
        f )
            traffic_from=$OPTARG
            ;;
        t )
            targets_file=$OPTARG
            ;;
        o )
            output_file=$OPTARG
            ;;
        \? )
            usage
            ;;
        : )
            echo "Error: -${OPTARG} requires an argument."
            usage
            ;;
    esac
done
shift $((OPTIND -1))

# Check required args
if [ -z "$traffic_from" ] || [ -z "$targets_file" ] || [ -z "$output_file" ] || [ "$#" -lt 1 ]; then
    usage
fi

# Verify target file
if [ ! -f "$targets_file" ]; then
    echo "Error: Target file '$targets_file' not found."
    exit 1
fi

# Load targets
mapfile -t targets < "$targets_file"

# Detect source IP
source_ip=$(ip -o -4 addr show | awk '!/127.0.0.1/ {print $4}' | cut -d/ -f1 | head -n1)
if [ -z "$source_ip" ]; then
    echo "Error: Unable to determine source IP."
    exit 1
fi

# Combine and parse Nmap outputs
nmap_outputs="$@"
combined_ips_and_ports=$(awk '
    /Nmap scan report for/ {
        ip = $NF
    }
    /open/ {
        split($1, port_info, "/")
        port = port_info[1]
        protocol = port_info[2]
        service = $3
        if (protocol == "tcp" || protocol == "udp") {
            print ip ":" port ":" protocol ":" service
        }
    }
' $nmap_outputs | sort -t: -k1,1V -k2,2n -k3,3 -k4,4 | uniq)

# Prepare output
csv_output=$(mktemp)
terminal_output=$(mktemp)
html_output="${output_file%.csv}.html"

# Headers
echo "Traffic From,Traffic To,Status,Source IP,Destination IP,Open Ports,Notes" > "$csv_output"

cat > "$html_output" <<'EOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>segcheck - Network Segmentation Validation Tool</title>

<style>
body {
  font-family: Arial, sans-serif;
  background: #f4f6f8;
  padding: 24px;
}

h1, h2, h3 {
  margin-bottom: 5px;
}

.summary {
  margin-bottom: 20px;
  font-size: 16px;
}

button {
  padding: 8px 14px;
  margin-right: 10px;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-weight: bold;
}

.btn-all { background:#4a90e2; color:white; }
.btn-pass { background:#27ae60; color:white; }
.btn-fail { background:#c0392b; color:white; }

table {
  border-collapse: collapse;
  width: 100%;
  background: white;
  box-shadow: 0 3px 10px rgba(0,0,0,0.08);
}

th, td {
  border: 1px solid #ddd;
  padding: 10px;
  text-align: center;
}

thead {
  position: sticky;
  top: 0;
  z-index: 5;
}

thead th {
  background: #c9d7ef;
}

tbody tr:nth-child(even) {
  background: #eef3fb;
}

td:last-child {
  text-align: left;
  max-width: 420px;
  word-wrap: break-word;
  white-space: normal;
}

.status-pass { color: #1e8449; font-weight: bold; }
.status-fail { color: #c0392b; font-weight: bold; }

</style>

<script>
function filterRows(type) {
  let rows = document.querySelectorAll("tbody tr");
  rows.forEach(r => {
    if (type === "ALL") r.style.display = "";
    else r.style.display = r.dataset.status === type ? "" : "none";
  });
}

function sortTable(n) {
  let table = document.getElementById("resultTable");
  let rows = Array.from(table.rows).slice(2);
  let asc = table.dataset.sort != n;
  table.dataset.sort = asc ? n : "";

  rows.sort((a,b) => {
    let x=a.cells[n].innerText;
    let y=b.cells[n].innerText;
    return asc ? x.localeCompare(y,undefined,{numeric:true})
               : y.localeCompare(x,undefined,{numeric:true});
  });

  rows.forEach(r => table.appendChild(r));
}
</script>

</head>
<body>

<h1>segcheck</h1>
<h2>Network Segmentation Validation Tool</h2>
<h3>Network Segmentation Test Netcat Results</h3>

<div class="summary" id="summaryBox">
Loading summary…
</div>

<button class="btn-all" onclick="filterRows('ALL')">Show All</button>
<button class="btn-pass" onclick="filterRows('PASS')">PASS Only</button>
<button class="btn-fail" onclick="filterRows('FAIL')">FAIL Only</button>

<br><br>

<table id="resultTable">
<thead>
<tr>
  <th rowspan="2" onclick="sortTable(0)">Traffic From</th>
  <th rowspan="2" onclick="sortTable(1)">Traffic To</th>
  <th rowspan="2" onclick="sortTable(2)">Status</th>
  <th colspan="4">Details</th>
</tr>
<tr>
  <th onclick="sortTable(3)">Source IP</th>
  <th onclick="sortTable(4)">Destination IP</th>
  <th onclick="sortTable(5)">Open Ports</th>
  <th onclick="sortTable(6)">Notes</th>
</tr>
</thead>
<tbody>
EOF

{
    echo -e "======================================="
    echo -e "segcheck"
    echo -e "Network Segmentation Validation Tool"
    echo -e "=======================================\n\n"

    echo -e "Network Segmentation Test Netcat Results\n"
    printf "%-17s %-25s %-8s %-17s %-16s %-20s %-30s\n" "Traffic From" "Traffic To" "Status" "Source IP" "Destination IP" "Open Ports" "Notes"
    printf "%-17s %-25s %-8s %-17s %-16s %-20s %-30s\n" "-------------" "------------------------" "------" "--------------" "--------------" "----------" "-----"
} > "$terminal_output"

any_fail_found=false
pass_count=0
fail_count=0

# Function to determine "Traffic To"
find_traffic_to() {
    local ip="$1"

    # Check exact IP match
    for t in "${targets[@]}"; do
        if [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            if [[ "$t" == "$ip" ]]; then
                echo "$t"
                return
            fi
        fi
    done

    # Check subnet match
    for t in "${targets[@]}"; do
        if [[ "$t" =~ / ]]; then
            if ipcalc -c "$ip" "$t" &>/dev/null; then
                echo "$t"
                return
            fi
        fi
    done

    # Check hostname match (reverse DNS)
    for t in "${targets[@]}"; do
        if [[ ! "$t" =~ ^[0-9] ]]; then
            host_ip=$(dig +short "$t" | head -n1)
            if [ -n "$host_ip" ] && [ "$host_ip" == "$ip" ]; then
                echo "$t"
                return
            fi
        fi
    done

    echo "Unknown"
}

# ======= MAIN LOGIC =======

if [ -z "$combined_ips_and_ports" ]; then
    for target in "${targets[@]}"; do
        printf "%s,%s,%s,%s,%s,%s,%s\n" "$traffic_from" "$target" "PASS" "$source_ip" "N/A" "N/A" "No open ports detected" >> "$csv_output"
        printf "%-17s %-25s %-8s %-17s %-16s %-20s %-30s\n" "$traffic_from" "$target" "PASS" "$source_ip" "N/A" "N/A" "No open ports detected" >> "$terminal_output"
        
        pass_count=$((pass_count+1))
        printf "<tr data-status='PASS'><td>%s</td><td>%s</td><td class='status-pass'>PASS</td><td>%s</td><td>N/A</td><td>N/A</td><td>No open ports detected</td></tr>\n" \
        "$traffic_from" "$target" "$source_ip" >> "$html_output"
    done
else
    for entry in $combined_ips_and_ports; do
        ip=$(echo $entry | cut -d: -f1)
        port=$(echo $entry | cut -d: -f2)
        protocol=$(echo $entry | cut -d: -f3)
        service=$(echo $entry | cut -d: -f4)

        traffic_to=$(find_traffic_to "$ip")
        status="PASS"
        notes=""

        if [ "$protocol" == "tcp" ]; then
            # First run (discarded for status, but keep output for notes)
            nc_out1=$(nc -zvv $ip $port 2>&1)

            # Second run determines status and notes
            nc_out2=$(nc -zvvv $ip $port 2>&1)
            if echo "$nc_out2" | grep -Ei "(open|succeeded)" &>/dev/null; then
                status="FAIL"
                any_fail_found=true
            else
                status="PASS"
            fi

            note1=$(echo "$nc_out1" | grep -Ei "(open|succeeded|refused)" | sed 's/^.*: //')
            note2=$(echo "$nc_out2" | grep -Ei "(open|succeeded|refused)" | sed 's/^.*: //')

            notes_plain="Run1: $note1 | Run2: $note2 (TCP)"
            notes_csv="Run1: $note1 | Run2: $note2 (TCP)"
            notes_html="Run1: $note1<br>Run2: $note2 (TCP)"

        elif [ "$protocol" == "udp" ]; then
            # First run (discarded for status, but keep output for notes)
            nc_out1=$(nc -uzvv $ip $port -w 1 2>&1)

            # Second run determines status and notes
            nc_out2=$(nc -uzvvv $ip $port -w 1 2>&1)
            if echo "$nc_out2" | grep -Ei "(open|succeeded)" &>/dev/null; then
                status="FAIL"
                any_fail_found=true
            else
                status="PASS"
            fi

            note1=$(echo "$nc_out1" | grep -Ei "(open|succeeded|refused)" | sed 's/^.*: //')
            note2=$(echo "$nc_out2" | grep -Ei "(open|succeeded|refused)" | sed 's/^.*: //')

            notes_plain="Run1: $note1 | Run2: $note2 (UDP)"
            notes_csv="Run1: $note1 | Run2: $note2 (UDP)"
            notes_html="Run1: $note1<br>Run2: $note2 (UDP)"

        fi



        printf "%s,%s,%s,%s,%s,%s,\"%b\"\n" \
        "$traffic_from" "$traffic_to" "$status" "$source_ip" "$ip" "$port/$protocol" "$notes_csv" >> "$csv_output"

        # ----- TERMINAL OUTPUT -----
        printf "%-17s %-25s %-8s %-17s %-16s %-20s %s\n" \
        "$traffic_from" "$traffic_to" "$status_colored" "$source_ip" "$ip" "$port/$protocol" \
        "Run1: $note1" >> "$terminal_output"

        printf "%-17s %-25s %-8s %-17s %-16s %-20s %s\n" \
        "" "" "" "" "" "" \
        "Run2: $note2 ($protocol)" >> "$terminal_output"


        if [ "$status" = "FAIL" ]; then
            status_class="status-fail"
            status_colored="${RED}FAIL${NC}"
            fail_count=$((fail_count+1))
        else
            status_class="status-pass"
            status_colored="${GREEN}PASS${NC}"
            pass_count=$((pass_count+1))
        fi


        printf "<tr data-status='%s'><td>%s</td><td>%s</td><td class='%s'>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" \
        "$status" "$traffic_from" "$traffic_to" "$status_class" "$status" "$source_ip" "$ip" "$port/$protocol" "$notes_html" >> "$html_output"

    done
fi

# Final PASS message
if [ "$any_fail_found" = false ]; then
    printf "\nSegmentation Pass\n\n" >> "$csv_output"
    printf "\nSegmentation Pass\n\n" >> "$terminal_output"
fi

cat "$terminal_output"
cat "$csv_output" > "$output_file"
printf "\nResults saved to %s and %s\n" "$output_file" "$html_output"

cat >> "$html_output" <<EOF
</tbody>
</table>

<script>
document.getElementById("summaryBox").innerHTML =
"PASS: $pass_count &nbsp;&nbsp; FAIL: $fail_count &nbsp;&nbsp; Total: $((pass_count+fail_count))";
</script>

</body>
</html>
EOF
