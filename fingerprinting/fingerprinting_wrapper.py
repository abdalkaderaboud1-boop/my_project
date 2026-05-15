import datetime
import json
import os
import re
import shlex
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


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "target"


def load_targets() -> list[str]:
    fallback = os.getenv("TARGET_URL", STATIC_TARGET)
    raw_targets = os.getenv("TARGETS_JSON")
    if not raw_targets:
        return [normalize_target_url(fallback)]

    try:
        parsed = json.loads(raw_targets)
    except json.JSONDecodeError:
        return [normalize_target_url(fallback)]

    if not isinstance(parsed, list):
        return [normalize_target_url(fallback)]

    targets = []
    seen = set()
    for item in parsed:
        if isinstance(item, str):
            normalized = normalize_target_url(item.strip())
            if normalized and normalized not in seen:
                seen.add(normalized)
                targets.append(normalized)

    return targets or [normalize_target_url(fallback)]


def scan_website():
    """فحص الموقع والكشف عن التقنيات المستخدمة."""
    try:
        targets = load_targets()
        mode = os.getenv("SCAN_MODE", STATIC_MODE).lower().strip()
        if mode not in ["quick", "deep"]:
            mode = STATIC_MODE

        print(f"\n[*] Fingerprinting Started | Targets: {targets} | Mode: {mode}")

        per_target_results = {}

        for target_url in targets:
            host = extract_host(target_url)
            target_key = safe_filename(host or target_url)

            try:
                whatweb_result = run_command(f"whatweb --no-errors -a 3 {shlex.quote(target_url)}", timeout=600)
            except Exception as e:
                whatweb_result = {"error": str(e)}

            try:
                wafw00f_result = run_command(f"wafw00f {shlex.quote(target_url)}", timeout=600)
            except Exception as e:
                wafw00f_result = {"error": str(e)}

            try:
                if mode == "deep":
                    httprobe_cmd = (
                        f'echo {shlex.quote(host)} | httprobe -p http:80 -p https:443 -p http:8080 -p https:8443'
                    )
                else:
                    httprobe_cmd = f'echo {shlex.quote(host)} | httprobe'
                httprobe_result = run_command(httprobe_cmd, timeout=300)
            except Exception as e:
                httprobe_result = {"error": str(e)}

            discovered_targets = [target_url]
            if isinstance(httprobe_result, dict):
                stdout_lines = httprobe_result.get("stdout")
                if isinstance(stdout_lines, list):
                    for line in stdout_lines:
                        if isinstance(line, str) and line.strip():
                            discovered_targets.append(normalize_target_url(line.strip()))

            per_target_results[target_key] = {
                "target": target_url,
                "host": host,
                "whatweb": whatweb_result,
                "wafw00f": wafw00f_result,
                "httprobe": httprobe_result,
                "discovered_targets": list(dict.fromkeys(discovered_targets)),
            }

        report = {
            "metadata": {
                "service": "fingerprinting-container",
                "targets": targets,
                "mode": mode,
                "timestamp": datetime.datetime.now().isoformat(),
                "status": "completed",
            },
            "results": {
                "per_target": per_target_results,
                "discovered_targets": list(
                    dict.fromkeys(
                        target
                        for target_result in per_target_results.values()
                        for target in target_result.get("discovered_targets", [])
                    )
                ),
            },
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