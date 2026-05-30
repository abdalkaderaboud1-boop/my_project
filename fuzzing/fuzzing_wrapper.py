import subprocess
import json
import os
import datetime
import re
import shlex
from pathlib import Path

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


def normalize_target(target):
    if target.startswith("http://") or target.startswith("https://"):
        return target.rstrip("/")
    return f"http://{target.rstrip('/')}"


def safe_filename(value):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "target"


def load_targets():
    fallback = os.getenv("TARGET_URL", DEFAULT_TARGET)
    raw_targets = os.getenv("TARGETS_JSON")
    if not raw_targets:
        return [normalize_target(fallback)]

    try:
        parsed = json.loads(raw_targets)
    except json.JSONDecodeError:
        return [normalize_target(fallback)]

    if not isinstance(parsed, list):
        return [normalize_target(fallback)]

    targets = []
    seen = set()
    for item in parsed:
        if isinstance(item, str):
            normalized = normalize_target(item.strip())
            if normalized and normalized not in seen:
                seen.add(normalized)
                targets.append(normalized)

    return targets or [normalize_target(fallback)]


def build_wordlist(mode):
    words = [
        "admin",
        "login",
        "dashboard",
        "uploads",
        "backup",
        "api",
        "robots.txt",
        "config",
        "test",
        "tmp",
        "assets",
        "static",
    ]

    if mode == "deep":
        words.extend([
            "phpinfo.php",
            "index.php",
            "old",
            "dev",
            "staging",
            "server-status",
            "admin.php",
            "shell.php",
        ])

    wordlist_path = "/tmp/fuzzing_wordlist.txt"
    with open(wordlist_path, "w") as f:
        f.write("\n".join(words) + "\n")
    return wordlist_path


def extract_discovered_targets(ffuf_output, gobuster_output, base_url):
    discovered = [base_url]

    try:
        ffuf_data = json.loads(Path(ffuf_output).read_text())
        results = ffuf_data.get("results", []) if isinstance(ffuf_data, dict) else []
        if isinstance(results, list):
            for item in results:
                if not isinstance(item, dict):
                    continue
                url = item.get("url") or item.get("redirectlocation")
                if isinstance(url, str) and url.strip():
                    discovered.append(url.strip())
    except Exception:
        pass

    try:
        for line in Path(gobuster_output).read_text(errors="ignore").splitlines():
            cleaned = line.strip()
            if not cleaned:
                continue
            if cleaned.startswith("/"):
                discovered.append(base_url.rstrip("/") + cleaned)
            elif cleaned.startswith("http://") or cleaned.startswith("https://"):
                discovered.append(cleaned)
    except Exception:
        pass

    return list(dict.fromkeys(discovered))


def main():
    targets = load_targets()
    mode = os.getenv("SCAN_MODE", DEFAULT_MODE).lower()

    report = {
        "metadata": {
            "container": "fuzzing_container",
            "targets": targets,
            "mode": mode,
            "start_time": datetime.datetime.now().isoformat()
        },
        "results": {}
    }

    wordlist = build_wordlist(mode)
    per_target_results = {}

    for target in targets:
        base_url = normalize_target(target)
        target_key = safe_filename(base_url)
        ffuf_output = f"/app/results/ffuf_output_{target_key}.json"
        gobuster_output = f"/app/results/gobuster_output_{target_key}.txt"

        if mode == "deep":
            ffuf_cmd = f"ffuf -k -u {shlex.quote(base_url + '/FUZZ')} -w {shlex.quote(wordlist)} -of json -o {shlex.quote(ffuf_output)} -mc all -timeout 10"
            gobuster_cmd = f"gobuster dir -k --retry -u {shlex.quote(base_url)} -w {shlex.quote(wordlist)} -q -o {shlex.quote(gobuster_output)} -x php,txt,html,bak,old || true"
        else:
            ffuf_cmd = f"ffuf -k -u {shlex.quote(base_url + '/FUZZ')} -w {shlex.quote(wordlist)} -of json -o {shlex.quote(ffuf_output)} -mc all -timeout 10"
            gobuster_cmd = f"gobuster dir -k --retry -u {shlex.quote(base_url)} -w {shlex.quote(wordlist)} -q -o {shlex.quote(gobuster_output)} || true"

        ffuf_ok = run_tool("ffuf", ffuf_cmd)
        gobuster_ok = run_tool("gobuster", gobuster_cmd)

        per_target_results[target_key] = {
            "target": target,
            "base_url": base_url,
            "ffuf_status": "Completed" if ffuf_ok else "Failed",
            "ffuf_output": ffuf_output if ffuf_ok else None,
            "gobuster_status": "Completed" if gobuster_ok else "Failed",
            "gobuster_output": gobuster_output if gobuster_ok else None,
            "discovered_targets": extract_discovered_targets(ffuf_output, gobuster_output, base_url)
            if ffuf_ok or gobuster_ok
            else [base_url],
        }

    report["results"]["per_target"] = per_target_results
    report["results"]["discovered_targets"] = list(
        dict.fromkeys(
            target
            for target_result in per_target_results.values()
            for target in target_result.get("discovered_targets", [])
        )
    )
    report["results"]["ffuf_status"] = "Completed" if all(
        item["ffuf_status"] == "Completed" for item in per_target_results.values()
    ) else "Partial"
    report["results"]["gobuster_status"] = "Completed" if all(
        item["gobuster_status"] == "Completed" for item in per_target_results.values()
    ) else "Partial"

    with open("/app/results/fuzzing_master_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("[+] Fuzzing Container: Tasks finished.")


if __name__ == "__main__":
    main()