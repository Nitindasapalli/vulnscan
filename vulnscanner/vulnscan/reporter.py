# vulnscan/reporter.py
import os
import json
from rich.console import Console
from rich.table import Table
from jinja2 import Template
from pathlib import Path

console = Console()

def write_json_report(summary: dict, output_dir: str):
    out = Path(output_dir) / "scan_summary.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    console.log(f"JSON report written to {out}")

def write_markdown_report(summary: dict, output_dir: str):
    lines = ["# Scan Summary\n"]
    for host in summary.get("hosts", []):
        lines.append(f"## Host `{host['ip']}`\n")
        if host.get("os"):
            lines.append("**OS guesses:**\n")
            for os_ in host["os"]:
                lines.append(f"- {os_['name']} (accuracy {os_['accuracy']})\n")
        lines.append("\n**Open ports:**\n")
        for p in host.get("ports", []):
            lines.append(f"- {p['port']}/{p['protocol']}: {p['service']} {p.get('product','')} {p.get('version','')}\n")
            for f in p.get("findings", []):
                lines.append(f"  - [!] {f['id']}: {f['notes']}\n")
        lines.append("\n")
    out = Path(output_dir) / "scan_summary.md"
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    console.log(f"Markdown report written to {out}")

def print_summary(summary: dict):
    table = Table(title="Scan Summary")
    table.add_column("Host")
    table.add_column("Open Ports")
    table.add_column("Findings")
    for host in summary.get("hosts", []):
        ports = ", ".join([p["port"] + "/" + p["protocol"] for p in host.get("ports", []) if p.get("state")=="open"])
        findings = []
        for p in host.get("ports", []):
            for f in p.get("findings", []):
                findings.append(f"{p['port']}/{p['protocol']}:{f['id']}")
        table.add_row(host["ip"], ports or "-", ", ".join(findings) or "-")
    console.print(table)
