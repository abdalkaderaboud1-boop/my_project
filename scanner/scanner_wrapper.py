import datetime
import json
import os
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
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


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "target"


def load_targets() -> list[str]:
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


def extract_discovered_targets(xml_output: str) -> list[str]:
    discovered = []
    seen = set()

    try:
        tree = ET.parse(xml_output)
    except Exception:
        return discovered

    root = tree.getroot()
    for host in root.findall("host"):
        addresses = []
        for address in host.findall("address"):
            addr_value = address.get("addr")
            if addr_value:
                addresses.append(addr_value)

        hostnames = []
        hostnames_node = host.find("hostnames")
        if hostnames_node is not None:
            for hostname in hostnames_node.findall("hostname"):
                hostname_value = hostname.get("name")
                if hostname_value:
                    hostnames.append(hostname_value)

        port_nodes = host.find("ports")
        open_ports = []
        if port_nodes is not None:
            for port in port_nodes.findall("port"):
                state = port.find("state")
                service = port.find("service")
                if state is None or state.get("state") != "open":
                    continue

                port_id = port.get("portid")
                service_name = service.get("name") if service is not None else None
                tunnel = service.get("tunnel") if service is not None else None

                if port_id and (
                    (service_name and service_name.startswith("http"))
                    or tunnel == "ssl"
                    or port_id in {"80", "443", "8080", "8443", "8000", "3000"}
                ):
                    open_ports.append(port_id)

        for hostname_value in hostnames:
            if hostname_value not in seen:
                seen.add(hostname_value)
                discovered.append(hostname_value)

        for address_value in addresses:
            for port_id in open_ports:
                http_url = f"http://{address_value}:{port_id}"
                https_url = f"https://{address_value}:{port_id}"
                for candidate in (http_url, https_url):
                    if candidate not in seen:
                        seen.add(candidate)
                        discovered.append(candidate)

    return discovered


def main():
    targets = load_targets()
    mode = os.getenv("SCAN_MODE", DEFAULT_MODE).lower()

    report = {
        "metadata": {
            "container": "network_scanner",
            "targets": targets,
            "mode": mode,
            "start_time": datetime.datetime.now().isoformat(),
        },
        "results": {},
    }

    per_target_results = {}
    for target in targets:
        xml_output = f"/app/results/nmap_output_{safe_filename(target)}.xml"

        if mode == "deep":
            nmap_cmd = f"nmap -p- -sV -A -oX {shlex.quote(xml_output)} {shlex.quote(target)}"
        else:
            nmap_cmd = f"nmap -F -sV --version-light -oX {shlex.quote(xml_output)} {shlex.quote(target)}"

        run_ok = run_tool("Nmap", nmap_cmd)
        per_target_results[target] = {
            "nmap_status": "Completed" if run_ok else "Failed",
            "raw_xml": xml_output if run_ok else None,
            "discovered_targets": extract_discovered_targets(xml_output) if run_ok else [],
        }

    report["results"]["per_target"] = per_target_results
    report["results"]["discovered_targets"] = []
    for target_result in per_target_results.values():
        report["results"]["discovered_targets"].extend(target_result.get("discovered_targets", []))
    report["results"]["discovered_targets"] = list(dict.fromkeys(report["results"]["discovered_targets"]))
    report["results"]["nmap_status"] = "Completed" if all(
        item["nmap_status"] == "Completed" for item in per_target_results.values()
    ) else "Partial"

    with open("/app/results/scanner_master_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("[+] Scanner Container: Tasks finished.")


if __name__ == "__main__":
    main()