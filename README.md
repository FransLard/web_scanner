# Web Security Scanner

A cybersecurity portfolio project — multi-mode web scanner for port scanning, technology detection, and basic vulnerability assessment.

## Features

| Mode | Description |
|------|-------------|
| `scan` | Async TCP port scanner with banner grabbing |
| `tech` | Web technology detection (server, framework, CMS) |
| `vuln` | Basic SQLi & reflected XSS scanner |
| `full` | Run all scans in one command |

## Quick Start

```bash
pip install -r requirements.txt

python main.py scan scanme.nmap.org
python main.py scan scanme.nmap.org --ports 22,80,443
python main.py scan scanme.nmap.org --all -o report.json

python main.py tech scanme.nmap.org

python main.py vuln "http://testphp.vulnweb.com/listproducts.php?cat=1"

python main.py full scanme.nmap.org -o report.txt
```

## Disclaimer

For educational and authorized testing only. Do not scan targets without permission.

## Tech Stack

- Python 3 — asyncio, sockets, argparse
- requests — HTTP client
- colorama — terminal output
