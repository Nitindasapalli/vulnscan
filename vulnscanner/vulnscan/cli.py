# vulnscan/cli.py
import argparse
from vulnscan.scanner import run_nmap
from vulnscan.parser import parse_nmap_xml
from vulnscan.reporter import write_json_report, write_markdown_report, print_summary

def main():
    p = argparse.ArgumentParser(description="VulnScan - simple nmap wrapper")
    p.add_argument("target", help="Target host or CIDR (e.g. 10.0.0.0/24 or example.com)")
    p.add_argument("-o", "--output", default="reports", help="Output directory")
    p.add_argument("-s", "--scan-type", choices=["quick", "default", "intense"], default="default")
    p.add_argument("--no-xml", action="store_true", help="Don't save raw nmap xml")
    args = p.parse_args()

    xml_path = run_nmap(args.target, args.output, profile=args.scan_type)
    summary = parse_nmap_xml(xml_path)
    write_json_report(summary, args.output)
    write_markdown_report(summary, args.output)
    print_summary(summary)

if __name__ == "__main__":
    main()
