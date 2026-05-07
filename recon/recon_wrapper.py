import datetime
import json
import os
import subprocess
from urllib.parse import urlparse

DEFAULT_TARGET = "testphp.vulnweb.com"
DEFAULT_MODE = "quick"


def run_command(command, timeout=600):
    print(f"[*] Running: {command}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, shell=True, timeout=timeout)
        return result.stdout.splitlines()
    except subprocess.TimeoutExpired:
        print("[!] Warning: Command timed out.")
        return []
    except Exception as e:
        print(f"[!] Error: {e}")
        return []


def normalize_target(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        return parsed.netloc or parsed.path
    return target


def main():
    target = normalize_target(os.getenv("TARGET_URL", DEFAULT_TARGET))
    mode = os.getenv("SCAN_MODE", DEFAULT_MODE).lower()

    print(f"[*] Recon Phase Started | Target: {target} | Mode: {mode}")

    subdomains = set()

    print("[+] Running Passive Discovery (Subfinder)...")
    subfinder_res = run_command(f"subfinder -d {target} -silent")
    subdomains.update(subfinder_res)

    if mode == "deep":
        print("[+] Running Active Discovery (Amass Active)...")
        amass_res = run_command(f"amass enum -active -d {target} -max-dns-queries 100")
        subdomains.update(amass_res)
    else:
        print("[-] Skipping Active Phase (Quick Mode selected)")

    report = {
        "metadata": {
            "container": "recon_container",
            "target": target,
            "mode": mode,
            "timestamp": datetime.datetime.now().isoformat(),
        },
        "results": {
            "count": len(subdomains),
            "subdomains": list(subdomains),
        },
    }

    with open("/app/results/recon_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print(f"[✓] Recon finished. Total subdomains found: {len(subdomains)}")


if __name__ == "__main__":
    main()