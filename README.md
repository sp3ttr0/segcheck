# segcheck

**segcheck** is a lightweight Bash tool for validating network segmentation controls using Nmap scan results + Netcat verification.

It parses Nmap output, tests connectivity to discovered open ports using Netcat (twice), and generates:

📄 CSV report

🌐 Interactive HTML report

🖥️ Colored terminal output



## 🖥️ Terminal
```bash
========================================
 segcheck
 Network Segmentation Validation Tool
========================================

Traffic From   Traffic To   Status   Source IP   Destination IP   Open Ports   Notes
-------------------------------------------------------------------------------------
10.1.42.0/24   serverA      PASS     10.1.42.5   10.1.50.10       443/tcp      Run1: refused
                                                                          Run2: refused (TCP)
10.1.42.0/24   serverB      FAIL     10.1.42.5   10.1.60.20       22/tcp       Run1: succeeded
                                                                          Run2: succeeded (TCP)
```


## ⚙️ Requirements
```
bash
nmap
netcat (nc)
ipcalc
dig (for hostname resolution)
```


## 📥 Installation
```bash
git clone https://github.com/spettro/segcheck.git
cd segcheck
chmod +x segcheck.sh
```


## 🧪 Usage
```bash
./segcheck.sh -f <traffic_from_subnet> -t <targets_file> -o <output.csv> <nmap_output_files...>
```


## 📌 Arguments
```bash
| Option | Description                               |
| ------ | ----------------------------------------- |
| `-f`   | Source subnet (Traffic From)              |
| `-t`   | Targets file (IPs, subnets, or hostnames) |
| `-o`   | Output CSV file (HTML is auto-generated)  |
```


