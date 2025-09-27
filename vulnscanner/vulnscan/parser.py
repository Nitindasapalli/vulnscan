# vulnscan/parser.py
import xml.etree.ElementTree as ET
import json
import re
from pathlib import Path

FINGERPRINTS_PATH = Path(__file__).parent / "fingerprints.json"

def load_fingerprints():
    with open(FINGERPRINTS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def match_fingerprints(service_name: str, product: str, version: str, fingerprints: dict):
    findings = []
    text = " ".join(filter(None, [service_name or "", product or "", version or ""]))
    for key, info in fingerprints.items():
        for pattern in info.get("match", []):
            if pattern.lower() in text.lower():
                findings.append({
                    "id": key,
                    "notes": info.get("notes"),
                    "cve_hint": info.get("cve_hint", [])
                })
                break
    return findings

def parse_nmap_xml(xml_path: str):
    fingerprints = load_fingerprints()
    tree = ET.parse(xml_path)
    root = tree.getroot()

    result = {"hosts": []}
    for host in root.findall("host"):
        addr_el = host.find("address")
        ip = addr_el.get("addr") if addr_el is not None else "unknown"
        host_obj = {"ip": ip, "ports": [], "os": []}

        # OS
        os_el = host.find("os")
        if os_el is not None:
            for osmatch in os_el.findall("osmatch"):
                host_obj["os"].append({
                    "name": osmatch.get("name"),
                    "accuracy": osmatch.get("accuracy")
                })

        # Ports
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                portid = port.get("portid")
                proto = port.get("protocol")
                state_el = port.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                service_el = port.find("service")
                service = service_el.get("name") if service_el is not None else None
                product = service_el.get("product") if service_el is not None else None
                version = service_el.get("version") if service_el is not None else None

                findings = match_fingerprints(service, product, version, fingerprints)

                host_obj["ports"].append({
                    "port": portid,
                    "protocol": proto,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                    "findings": findings
                })
        result["hosts"].append(host_obj)
    return result
