import subprocess
import json
import os
import datetime

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


def main():
    target = os.getenv("TARGET_URL", DEFAULT_TARGET)
    mode = os.getenv("SCAN_MODE", DEFAULT_MODE).lower()

    base_url = normalize_target(target)
    wordlist = build_wordlist(mode)

    report = {
        "metadata": {
            "container": "fuzzing_container",
            "target": target,
            "mode": mode,
            "start_time": datetime.datetime.now().isoformat()
        },
        "results": {}
    }

    ffuf_output = "/app/results/ffuf_output.json"
    gobuster_output = "/app/results/gobuster_output.txt"

    if mode == "deep":
        ffuf_cmd = f"ffuf -u {base_url}/FUZZ -w {wordlist} -of json -o {ffuf_output} -mc all -timeout 10"
        gobuster_cmd = f"gobuster dir -u {base_url} -w {wordlist} -q -o {gobuster_output} -x php,txt,html,bak,old"
    else:
        ffuf_cmd = f"ffuf -u {base_url}/FUZZ -w {wordlist} -of json -o {ffuf_output} -mc all -timeout 10"
        gobuster_cmd = f"gobuster dir -u {base_url} -w {wordlist} -q -o {gobuster_output}"

    if run_tool("ffuf", ffuf_cmd):
        report["results"]["ffuf_status"] = "Completed"
        report["results"]["ffuf_output"] = ffuf_output

    if run_tool("gobuster", gobuster_cmd):
        report["results"]["gobuster_status"] = "Completed"
        report["results"]["gobuster_output"] = gobuster_output

    with open("/app/results/fuzzing_master_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("[+] Fuzzing Container: Tasks finished.")


if __name__ == "__main__":
    main()