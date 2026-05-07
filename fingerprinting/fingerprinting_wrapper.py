import datetime
import json
import os
import subprocess
from urllib.parse import urlparse

STATIC_TARGET = "https://example.com/"
STATIC_MODE = "quick"


def run_command(command, timeout=600):
    """تنفيذ أوامر النظام وجمع النتائج"""
    print(f"[*] Running: {command}")
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=True,
            timeout=timeout,
        )
        out = result.stdout.strip().splitlines() if result.stdout else []
        err = result.stderr.strip().splitlines() if result.stderr else []
        return {"stdout": out, "stderr": err, "returncode": result.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": [], "stderr": ["Command timed out"], "returncode": -1}
    except Exception as e:
        return {"stdout": [], "stderr": [str(e)], "returncode": -1}


def extract_host(url: str) -> str:
    """يحصل على host:port من URL كامل."""
    p = urlparse(url)
    host = p.netloc or p.path
    if "@" in host:
        host = host.split("@", 1)[1]
    return host


def normalize_target_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target.rstrip("/")
    return f"http://{target.rstrip('/')}"


def scan_website():
    """فحص الموقع والكشف عن التقنيات المستخدمة."""
    try:
        target_url = normalize_target_url(os.getenv("TARGET_URL", STATIC_TARGET))
        mode = os.getenv("SCAN_MODE", STATIC_MODE).lower().strip()
        if mode not in ["quick", "deep"]:
            mode = STATIC_MODE

        host = extract_host(target_url)

        print(f"\n[*] Fingerprinting Started | Target: {target_url} | Host: {host} | Mode: {mode}")

        results = {}

        try:
            results["whatweb"] = run_command(f"whatweb --no-errors -a 3 {target_url}", timeout=600)
        except Exception as e:
            results["whatweb"] = {"error": str(e)}

        try:
            results["wafw00f"] = run_command(f"wafw00f {target_url}", timeout=600)
        except Exception as e:
            results["wafw00f"] = {"error": str(e)}

        try:
            if mode == "deep":
                results["httprobe"] = run_command(
                    f'echo "{host}" | httprobe -p http:80 -p https:443 -p http:8080 -p https:8443',
                    timeout=300,
                )
            else:
                results["httprobe"] = run_command(f'echo "{host}" | httprobe', timeout=300)
        except Exception as e:
            results["httprobe"] = {"error": str(e)}

        report = {
            "metadata": {
                "service": "fingerprinting-container",
                "target": target_url,
                "host": host,
                "mode": mode,
                "timestamp": datetime.datetime.now().isoformat(),
                "status": "completed",
            },
            "results": results,
        }

        os.makedirs("/app/results", exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"/app/results/fingerprinting_report_{timestamp}.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=4)

        print(f"[✓] Report saved: {report_file}")
        return report

    except Exception as e:
        print(f"[!] Fingerprinting failed: {e}")
        return {"error": str(e)}


def main():
    print("[*] Fingerprinting container started")
    scan_website()


if __name__ == "__main__":
    main()