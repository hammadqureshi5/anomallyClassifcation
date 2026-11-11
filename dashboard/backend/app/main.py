"""ACDS platform API: scans, findings, hosts, modules and dashboard stats."""

from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import db, runner
from .config import FRONTEND_DIST, SAMPLES_DIR, UPLOAD_DIR
from .modules import BY_ID, MODULES

app = FastAPI(title="ACDS Platform API", version="0.1.0")
db.init()

FINDING_STATUSES = {"open", "confirmed", "false_positive", "resolved"}


def _samples() -> list[dict]:
    index = SAMPLES_DIR / "samples.json"
    if not index.exists():
        return []
    samples = json.loads(index.read_text())
    return [s for s in samples if (SAMPLES_DIR / s["file"]).exists()]


@app.get("/api/health")
def health():
    return {"ok": True}


@app.get("/api/modules")
def modules():
    return [m.to_dict() for m in MODULES]


@app.get("/api/samples")
def samples():
    return [{k: s.get(k) for k in ("id", "name", "description", "module_ids", "rows")} for s in _samples()]


@app.post("/api/scans")
async def create_scan(name: str = Form(...), module_id: str = Form(...), sample_id: str | None = Form(None),
                      options: str = Form("{}"), file: UploadFile | None = File(None)):
    module = BY_ID.get(module_id)
    if module is None or not module.worker:
        raise HTTPException(400, f"Module {module_id!r} cannot run scans")
    ready, reason = module.readiness()
    if not ready:
        raise HTTPException(409, f"{module.name} is not ready: {reason}")
    try:
        opts = json.loads(options or "{}")
    except json.JSONDecodeError:
        raise HTTPException(400, "options must be a JSON object")
    defaults = {o["key"]: o["default"] for o in module.options}
    opts = {**defaults, **{k: v for k, v in opts.items() if k in defaults}}

    scan_id = uuid.uuid4().hex[:12]
    if file is not None and file.filename:
        if not file.filename.lower().endswith(".csv"):
            raise HTTPException(400, "Upload a .csv file")
        input_path = UPLOAD_DIR / f"{scan_id}.csv"
        with input_path.open("wb") as out:
            shutil.copyfileobj(file.file, out)
        input_name = Path(file.filename).name
    elif sample_id:
        sample = next((s for s in _samples() if s["id"] == sample_id), None)
        if sample is None:
            raise HTTPException(400, f"Unknown sample {sample_id!r}")
        input_path, input_name = SAMPLES_DIR / sample["file"], sample["name"]
    else:
        raise HTTPException(400, "Choose a sample or upload a CSV file")

    db.create_scan({"id": scan_id, "name": name.strip() or module.name, "module_id": module_id,
                    "created_at": db.now(), "input_name": input_name,
                    "input_path": str(input_path.resolve()), "options": opts})
    runner.submit(scan_id)
    return db.get_scan(scan_id)


@app.get("/api/scans")
def list_scans():
    return db.list_scans()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return scan


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str):
    runner.cancel(scan_id)
    if not db.delete_scan(scan_id):
        raise HTTPException(404, "Scan not found")
    (UPLOAD_DIR / f"{scan_id}.csv").unlink(missing_ok=True)
    return {"ok": True}


@app.get("/api/scans/{scan_id}/hosts")
def scan_hosts(scan_id: str):
    return db.hosts(scan_id=scan_id)


@app.get("/api/hosts")
def all_hosts():
    return db.hosts()


@app.get("/api/findings")
def findings(scan_id: str | None = None, severity: str | None = None, module_id: str | None = None,
             status: str | None = None, host: str | None = None, q: str | None = None,
             limit: int = 50, offset: int = 0):
    return db.list_findings(limit=min(max(limit, 1), 500), offset=max(offset, 0), scan_id=scan_id,
                            severity=severity, module_id=module_id, status=status, host=host, q=q)


@app.get("/api/findings/groups")
def finding_groups(scan_id: str | None = None):
    return db.finding_groups(scan_id)


class FindingUpdate(BaseModel):
    status: str | None = None
    feedback_note: str | None = None


@app.patch("/api/findings/{finding_id}")
def update_finding(finding_id: int, body: FindingUpdate):
    if body.status is not None and body.status not in FINDING_STATUSES:
        raise HTTPException(400, f"status must be one of {sorted(FINDING_STATUSES)}")
    finding = db.update_finding(finding_id, body.status, body.feedback_note)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    return finding


@app.get("/api/stats")
def stats():
    return db.stats()


# Serve the built React app (frontend/dist) with client-side routing fallback.
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            raise HTTPException(404, "Not found")
        target = FRONTEND_DIST / path
        if path and target.is_file() and FRONTEND_DIST in target.resolve().parents:
            return FileResponse(target)
        return FileResponse(FRONTEND_DIST / "index.html")
