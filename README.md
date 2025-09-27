# VulnScan – Custom Vulnerability Scanner (Python + Nmap)

## Project Overview
VulnScan is a Python-based vulnerability scanner that wraps around `nmap` to scan networks, detect open ports, identify services, and match them against a custom vulnerability fingerprint database.  
It generates **JSON** and **Markdown** reports for easy review and can be used to test servers and networks you own.

This project demonstrates practical cybersecurity skills suitable for CVs, portfolios, and interview demos.

---

## Features
- Run nmap scans with configurable profiles (`quick`, `default`, `intense`)
- Parse nmap XML output to extract hosts, open ports, services, and versions
- Match services and versions against a **local vulnerability fingerprint database**
- Produce **JSON** and **Markdown** reports
- Terminal summary with color-coded table output (using `rich`)
- Safe by default: no exploits or destructive scanning

---

## Installation

1. Clone the repository:

git clone https://github.com/<your-username>/vulnscan.git
cd vulnscan

2. Create a virtual environment and install dependencies:

python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

3. Ensure nmap is installed on your system:

sudo apt install nmap  # Ubuntu/Debian
or
brew install nmap      # macOS

# Usage
Run a scan on localhost:

python -m vulnscan.cli 127.0.0.1 -o reports

- 127.0.0.1 → Target IP or hostname

- -o reports → Output folder for XML, JSON, and Markdown reports

- -s quick|default|intense → Scan profile (optional)

View the Markdown report:

cat reports/scan_summary.md

# How It Works
Overview Diagram

[ Target Host ] 
      |
      v
   [ Nmap Scan ] -- Generates XML --> [ Parser ]
                                      |
                                      v
                                [ Fingerprint DB ]
                                      |
                                      v
                                [ JSON & Markdown Reports ]
                                      |
                                      v
                                [ Terminal Summary ]


Step-by-step:

1. User provides a target (IP or hostname) and optional scan profile.

2. Nmap is run with the selected options to detect open ports, services, and OS info.

3. The XML output from nmap is parsed using Python.

4. Each detected service/version is matched against a local fingerprint database for potential vulnerabilities.

5. JSON and Markdown reports are generated automatically.

6. Terminal summary table shows hosts, open ports, and matched vulnerabilities for a quick overview.
