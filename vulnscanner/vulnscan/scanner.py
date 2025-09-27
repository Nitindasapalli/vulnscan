# vulnscan/scanner.py
import os
import subprocess
from datetime import datetime

SCAN_PROFILES = {
    "quick": ["-sS", "-F", "-sV"],
    "default": ["-sS", "-sV", "-O", "-T4", "--reason", "--open"],
    "intense": ["-sS", "-sV", "-O", "-A", "-T4", "--reason", "--open"]
}

def run_nmap(target: str, output_dir: str = "reports", profile: str = "default") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    xml_file = os.path.join(output_dir, f"nmap_{target.replace('/', '_')}_{timestamp}.xml")

    flags = SCAN_PROFILES.get(profile, SCAN_PROFILES["default"])
    cmd = ["nmap", *flags, "-oX", xml_file, target]
    print("Running nmap:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    return xml_file
