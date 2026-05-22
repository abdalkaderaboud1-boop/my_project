from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import docker
from docker.errors import BuildError, ImageNotFound, APIError


SERVICE_ORDER = ["recon", "scanner", "fingerprinting", "fuzzing"]


@dataclass(frozen=True)
class ServiceSpec:
    name: str
    image_tag: str
    build_path: Path
    result_dir_name: str
    result_file_name: str | None = None
    result_prefix: str | None = None


class PipelineOrchestrator:
    def __init__(self) -> None:
        self.client = docker.from_env()
        self.host_project_root = Path(os.getenv("HOST_PROJECT_ROOT", "/home/mohammed/Works/Project/my_project/))
        self.runtime_root = self.host_project_root / "main" / "runtime"
        self.master_report_path = self.runtime_root / "master_report.json"
        self.state_path = self.runtime_root / "state.json"
        self.specs = self._build_service_specs()
        self.lock = threading.Lock()
        self.cancel_event = threading.Event()
        self.active_containers: dict[str, str] = {}
        self.active_job: dict[str, Any] | None = None
        self.worker_thread: threading.Thread | None = None
        self._ensure_runtime_dirs()

    def _build_service_specs(self) -> dict[str, ServiceSpec]:
        return {
            "recon": ServiceSpec(
                name="recon",
                image_tag="main/recon:latest",
                build_path=self.host_project_root / "recon",
                result_dir_name="recon",
                result_file_name="recon_report.json",
            ),
            "scanner": ServiceSpec(
                name="scanner",
                image_tag="main/scanner:latest",
                build_path=self.host_project_root / "scanner",
                result_dir_name="scanner",
                result_file_name="scanner_master_report.json",
            ),
            "fingerprinting": ServiceSpec(
                name="fingerprinting",
                image_tag="main/fingerprinting:latest",
                build_path=self.host_project_root / "fingerprinting",
                result_dir_name="fingerprinting",
                result_prefix="fingerprinting_report_",
            ),
            "fuzzing": ServiceSpec(
                name="fuzzing",
                image_tag="main/fuzzing:latest",
                build_path=self.host_project_root / "fuzzing",
                result_dir_name="fuzzing",
                result_file_name="fuzzing_master_report.json",
            ),
        }

    def _ensure_runtime_dirs(self) -> None:
        for service_name in SERVICE_ORDER:
            (self.runtime_root / service_name / "results").mkdir(parents=True, exist_ok=True)
        self.runtime_root.mkdir(parents=True, exist_ok=True)

    def validate_layout(self) -> None:
        missing = []
        for spec in self.specs.values():
            if not spec.build_path.exists():
                missing.append(str(spec.build_path))
            if not (spec.build_path / "Dockerfile").exists():
                missing.append(str(spec.build_path / "Dockerfile"))
            wrapper = spec.build_path / f"{spec.name}_wrapper.py"
            if not wrapper.exists():
                missing.append(str(wrapper))
        if missing:
            raise FileNotFoundError("Missing required project files: " + ", ".join(missing))

    def refresh_images(self, force: bool = True) -> dict[str, Any]:
        self.validate_layout()
        built: dict[str, Any] = {}
        for service_name in SERVICE_ORDER:
            spec = self.specs[service_name]
            try:
                if force:
                    image, logs = self.client.images.build(
                        path=str(spec.build_path),
                        tag=spec.image_tag,
                        rm=True,
                        forcerm=True,
                    )
                    built[service_name] = {
                        "image_id": getattr(image, "id", None),
                        "status": "built",
                        "logs": self._stringify_build_logs(logs),
                    }
                else:
                    self.client.images.get(spec.image_tag)
                    built[service_name] = {"status": "already-present"}
            except (BuildError, APIError, ImageNotFound) as exc:
                raise RuntimeError(f"Failed to prepare image for {service_name}: {exc}") from exc
        self._write_state({"status": "images-ready", "services": built, "updated_at": self._now()})
        return built

    def start_job(self, target: str, mode: str = "quick", rebuild_images: bool = True) -> dict[str, Any]:
        with self.lock:
            if self.active_job and self.active_job.get("status") == "running":
                raise RuntimeError("A job is already running")

            job_id = str(uuid.uuid4())
            self.cancel_event.clear()
            self.active_job = {
                "job_id": job_id,
                "target": target,
                "mode": mode,
                "status": "starting",
                "started_at": self._now(),
                "stages": [],
            }
            self._write_state(self.active_job)
            thread = threading.Thread(
                target=self._run_job,
                args=(job_id, target, mode, rebuild_images),
                daemon=True,
            )
            self.worker_thread = thread
            thread.start()
            return {"job_id": job_id, "status": "started"}

    def stop_job(self, reason: str | None = None) -> dict[str, Any]:
        self.cancel_event.set()
        stopped = []
        for service_name, container_id in list(self.active_containers.items()):
            try:
                container = self.client.containers.get(container_id)
                container.stop(timeout=5)
                stopped.append(service_name)
            except Exception:
                continue
        if self.active_job:
            self.active_job["status"] = "stopping"
            self.active_job["stop_reason"] = reason
            self._write_state(self.active_job)
        return {"status": "stop-requested", "stopped_services": stopped}

    def status(self) -> dict[str, Any]:
        data = self.active_job.copy() if self.active_job else {"status": "idle"}
        data["active_containers"] = dict(self.active_containers)
        data["master_report_path"] = str(self.master_report_path)
        return data

    def get_master_report(self) -> dict[str, Any] | None:
        if not self.master_report_path.exists():
            return None
        return json.loads(self.master_report_path.read_text())

    def _run_job(self, job_id: str, target: str, mode: str, rebuild_images: bool) -> None:
        try:
            if rebuild_images:
                self.refresh_images(force=True)

            self.active_job["status"] = "running"
            self._write_state(self.active_job)

            report = {
                "metadata": {
                    "job_id": job_id,
                    "target": target,
                    "mode": mode,
                    "status": "running",
                    "started_at": self._now(),
                },
                "stages": {},
                "pipeline_flow": [],
            }

            pipeline_targets = [target]

            for service_name in SERVICE_ORDER:
                if self.cancel_event.is_set():
                    report["metadata"]["status"] = "cancelled"
                    break
                stage_result = self._run_stage(service_name, target, mode, pipeline_targets)
                stage_result["input_targets"] = list(pipeline_targets)
                report["stages"][service_name] = stage_result
                self.active_job.setdefault("stages", []).append(stage_result)
                self._write_state(self.active_job)

                next_targets = self._derive_next_targets(service_name, stage_result, pipeline_targets)
                report["pipeline_flow"].append(
                    {
                        "stage": service_name,
                        "input_targets": list(pipeline_targets),
                        "output_targets": list(next_targets),
                        "input_count": len(pipeline_targets),
                        "output_count": len(next_targets),
                    }
                )

                if service_name == "recon":
                    pipeline_targets = next_targets
                    self.active_job["pipeline_targets"] = list(pipeline_targets)
                    self.active_job["pipeline_flow"] = list(report["pipeline_flow"])
                    self._write_state(self.active_job)
                elif service_name == "scanner":
                    pipeline_targets = next_targets
                    self.active_job["pipeline_targets"] = list(pipeline_targets)
                    self.active_job["pipeline_flow"] = list(report["pipeline_flow"])
                    self._write_state(self.active_job)
                elif service_name == "fingerprinting":
                    pipeline_targets = next_targets
                    self.active_job["pipeline_targets"] = list(pipeline_targets)
                    self.active_job["pipeline_flow"] = list(report["pipeline_flow"])
                    self._write_state(self.active_job)
                elif service_name == "fuzzing":
                    self.active_job["pipeline_targets"] = list(pipeline_targets)
                    self.active_job["pipeline_flow"] = list(report["pipeline_flow"])
                    self._write_state(self.active_job)

            report["metadata"]["completed_at"] = self._now()
            report["metadata"]["status"] = "cancelled" if self.cancel_event.is_set() else "completed"
            self.master_report_path.write_text(json.dumps(report, indent=4, ensure_ascii=False))
            self.active_job.update(
                {
                    "status": report["metadata"]["status"],
                    "completed_at": report["metadata"]["completed_at"],
                    "report_path": str(self.master_report_path),
                }
            )
            self._write_state(self.active_job)
        except Exception as exc:
            if self.active_job:
                self.active_job.update({"status": "failed", "error": str(exc), "completed_at": self._now()})
                self._write_state(self.active_job)
            self.master_report_path.write_text(
                json.dumps(
                    {
                        "metadata": {
                            "job_id": job_id,
                            "target": target,
                            "mode": mode,
                            "status": "failed",
                            "error": str(exc),
                            "completed_at": self._now(),
                        },
                        "stages": self.active_job.get("stages", []) if self.active_job else [],
                    },
                    indent=4,
                    ensure_ascii=False,
                )
            )
        finally:
            for container_id in list(self.active_containers.values()):
                try:
                    container = self.client.containers.get(container_id)
                    container.remove(force=True)
                except Exception:
                    continue
            self.active_containers.clear()

    def _run_stage(self, service_name: str, target: str, mode: str, targets: list[str]) -> dict[str, Any]:
        spec = self.specs[service_name]
        result_dir = self.runtime_root / service_name / "results"
        result_dir.mkdir(parents=True, exist_ok=True)

        container_name = f"main-{service_name}-{uuid.uuid4().hex[:8]}"
        container = self.client.containers.run(
            spec.image_tag,
            detach=True,
            name=container_name,
            environment={
                "TARGET_URL": target,
                "SCAN_MODE": mode,
                "TARGETS_JSON": json.dumps(targets),
            },
            volumes={str(result_dir): {"bind": "/app/results", "mode": "rw"}},
            remove=False,
        )
        self.active_containers[service_name] = container.id

        wait_result = container.wait()
        container.reload()
        logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        container.remove(force=True)
        self.active_containers.pop(service_name, None)

        result_path = self._resolve_result_path(spec, result_dir)
        result_content = None
        if result_path and result_path.exists():
            try:
                result_content = json.loads(result_path.read_text())
            except Exception:
                result_content = result_path.read_text(errors="replace")

        return {
            "service": service_name,
            "container_id": container.id,
            "exit_code": wait_result.get("StatusCode"),
            "result_path": str(result_path) if result_path else None,
            "result": result_content,
            "logs": logs,
            "status": "completed" if wait_result.get("StatusCode") == 0 else "failed",
        }

    def _derive_targets_from_recon(self, stage_result: dict[str, Any], fallback_target: str) -> list[str]:
        targets = [fallback_target]
        result = stage_result.get("result")
        if isinstance(result, dict):
            results_section = result.get("results")
            if isinstance(results_section, dict):
                discovered_targets = results_section.get("subdomains")
                if isinstance(discovered_targets, list):
                    for item in discovered_targets:
                        if isinstance(item, str) and item.strip():
                            targets.append(item.strip())
        return self._dedupe_targets(targets)

    def _derive_targets_from_scanner(self, stage_result: dict[str, Any], fallback_targets: list[str]) -> list[str]:
        targets = list(fallback_targets)
        result = stage_result.get("result")
        if isinstance(result, dict):
            results_section = result.get("results")
            if isinstance(results_section, dict):
                per_target = results_section.get("per_target")
                if isinstance(per_target, dict):
                    for target_result in per_target.values():
                        if not isinstance(target_result, dict):
                            continue
                        discovered_targets = target_result.get("discovered_targets")
                        if isinstance(discovered_targets, list):
                            for item in discovered_targets:
                                if isinstance(item, str) and item.strip():
                                    targets.append(item.strip())
        return self._dedupe_targets(targets)

    def _derive_targets_from_fingerprinting(self, stage_result: dict[str, Any], fallback_targets: list[str]) -> list[str]:
        targets = list(fallback_targets)
        result = stage_result.get("result")
        if isinstance(result, dict):
            results_section = result.get("results")
            if isinstance(results_section, dict):
                per_target = results_section.get("per_target")
                if isinstance(per_target, dict):
                    for target_result in per_target.values():
                        if not isinstance(target_result, dict):
                            continue
                        discovered_targets = target_result.get("discovered_targets")
                        if isinstance(discovered_targets, list):
                            for item in discovered_targets:
                                if isinstance(item, str) and item.strip():
                                    targets.append(item.strip())
        return self._dedupe_targets(targets)

    def _derive_targets_from_fuzzing(self, stage_result: dict[str, Any], fallback_targets: list[str]) -> list[str]:
        targets = list(fallback_targets)
        result = stage_result.get("result")
        if isinstance(result, dict):
            results_section = result.get("results")
            if isinstance(results_section, dict):
                per_target = results_section.get("per_target")
                if isinstance(per_target, dict):
                    for target_result in per_target.values():
                        if not isinstance(target_result, dict):
                            continue
                        discovered_targets = target_result.get("discovered_targets")
                        if isinstance(discovered_targets, list):
                            for item in discovered_targets:
                                if isinstance(item, str) and item.strip():
                                    targets.append(item.strip())
        return self._dedupe_targets(targets)

    def _derive_next_targets(self, service_name: str, stage_result: dict[str, Any], fallback_targets: list[str]) -> list[str]:
        if service_name == "recon":
            return self._derive_targets_from_recon(stage_result, fallback_targets[0] if fallback_targets else "")
        if service_name == "scanner":
            return self._derive_targets_from_scanner(stage_result, fallback_targets)
        if service_name == "fingerprinting":
            return self._derive_targets_from_fingerprinting(stage_result, fallback_targets)
        if service_name == "fuzzing":
            return self._derive_targets_from_fuzzing(stage_result, fallback_targets)
        return self._dedupe_targets(fallback_targets)

    def _dedupe_targets(self, targets: list[str]) -> list[str]:
        seen = set()
        ordered_targets = []
        for target in targets:
            cleaned = target.strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                ordered_targets.append(cleaned)
        return ordered_targets

    def _resolve_result_path(self, spec: ServiceSpec, result_dir: Path) -> Path | None:
        if spec.result_file_name:
            path = result_dir / spec.result_file_name
            return path if path.exists() else None
        if spec.result_prefix:
            matches = sorted(result_dir.glob(f"{spec.result_prefix}*.json"), key=lambda p: p.stat().st_mtime)
            return matches[-1] if matches else None
        return None

    def _write_state(self, payload: dict[str, Any]) -> None:
        self.state_path.write_text(json.dumps(payload, indent=4, ensure_ascii=False))

    def _stringify_build_logs(self, logs: list[Any]) -> list[str]:
        rendered = []
        for item in logs:
            if isinstance(item, dict) and "stream" in item:
                rendered.append(item["stream"].strip())
            else:
                rendered.append(str(item).strip())
        return [line for line in rendered if line]

    def _now(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%S%z")
