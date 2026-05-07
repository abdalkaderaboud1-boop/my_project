import datetime
import json
import os
import subprocess
from urllib.parse import urlparse

DEFAULT_TARGET = "testphp.vulnweb.com"
DEFAULT_MODE = "quick"


def run_tool(name, command):
    print(f"[*] Running {name}...")
    try:
        subprocess.run(command, shell=True, check=True)
        return True
    except Exception as e:
        print(f"[!] Error in {name}: {e}")
        return False


def normalize_target(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        return parsed.netloc or parsed.path
    return target


def main():
    target = normalize_target(os.getenv("TARGET_URL", DEFAULT_TARGET))
    mode = os.getenv("SCAN_MODE", DEFAULT_MODE).lower()

    report = {
        "metadata": {
            "container": "network_scanner",
            "target": target,
            "mode": mode,
            "start_time": datetime.datetime.now().isoformat(),
        },
        "results": {},
    }

    xml_output = "/app/results/nmap_output.xml"

    if mode == "deep":
        nmap_cmd = f"nmap -p- -sV -A -oX {xml_output} {target}"
    else:
        nmap_cmd = f"nmap -F -sV --version-light -oX {xml_output} {target}"

    if run_tool("Nmap", nmap_cmd):
        report["results"]["nmap_status"] = "Completed"
        report["results"]["raw_xml"] = xml_output

    with open("/app/results/scanner_master_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("[+] Scanner Container: Tasks finished.")


if __name__ == "__main__":
    main()