from __future__ import annotations

from fastapi import FastAPI, HTTPException

from orchestrator import PipelineOrchestrator
from schemas import PipelineRequest, RefreshRequest, StopRequest


app = FastAPI(
    title="Main Container Orchestrator",
    description="Central controller for recon, scanner, fingerprinting, and fuzzing containers.",
)

orchestrator = PipelineOrchestrator()


@app.on_event("startup")
def startup_event() -> None:
    orchestrator.refresh_images(force=True)


@app.get("/")
def root() -> dict:
    return {
        "name": "main-orchestrator",
        "status": "ready",
        "stages": ["recon", "scanner", "fingerprinting", "fuzzing"],
    }


@app.get("/health")
def health() -> dict:
    return {"status": "healthy"}


@app.get("/status")
def status() -> dict:
    return orchestrator.status()


@app.post("/maintenance/refresh")
def refresh_images(request: RefreshRequest) -> dict:
    try:
        return orchestrator.refresh_images(force=request.force)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/run")
def run_pipeline(request: PipelineRequest) -> dict:
    try:
        return orchestrator.start_job(request.target, request.mode, rebuild_images=False)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/stop")
def stop_pipeline(request: StopRequest) -> dict:
    return orchestrator.stop_job(request.reason)


@app.get("/report")
def report() -> dict:
    report_data = orchestrator.get_master_report()
    if report_data is None:
        raise HTTPException(status_code=404, detail="No master report available yet")
    return report_data


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
