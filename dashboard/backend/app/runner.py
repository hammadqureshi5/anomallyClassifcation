"""Runs scans by launching the module's worker inside the module's own Python environment.

Worker protocol (see workers/README.md):
  <python> workers/<worker>.py --input IN.csv --output OUT.json --options '{"k": "v"}'
  stderr lines "PROGRESS <0..1>" update the progress bar, all other lines go to the scan log.
  OUT.json = {"rows_scanned": int, "findings": [ {severity, title, ...}, ... ]}
"""

from __future__ import annotations

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor

from . import db
from .config import RESULTS_DIR, WORKERS_DIR
from .modules import BY_ID

MAX_FINDINGS_PER_SCAN = 5000

_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan")
_processes: dict[str, subprocess.Popen] = {}


def submit(scan_id: str) -> None:
    _pool.submit(_run, scan_id)


def cancel(scan_id: str) -> None:
    proc = _processes.get(scan_id)
    if proc and proc.poll() is None:
        proc.kill()


def _run(scan_id: str) -> None:
    scan = db.get_scan(scan_id, with_log=False)
    if scan is None:
        return
    module = BY_ID[scan["module_id"]]
    input_path, options = db.get_scan_input(scan_id)
    output_path = RESULTS_DIR / f"{scan_id}.json"
    db.update_scan(scan_id, status="running", started_at=db.now(), progress=0.02)
    log = lambda line: db.append_log(scan_id, line)  # noqa: E731

    ready, reason = module.readiness()
    if not ready:
        log(f"ERROR {reason}")
        db.update_scan(scan_id, status="failed", error=reason, finished_at=db.now())
        return

    cmd = [str(module.python), str(WORKERS_DIR / module.worker), "--input", input_path,
           "--output", str(output_path), "--options", json.dumps(options)]
    log(f"Module: {module.name} ({module.owner})")
    log(f"Input: {scan['input_name']}  Options: {json.dumps(options)}")
    log(f"Launching worker in {module.directory}")
    try:
        proc = subprocess.Popen(cmd, cwd=module.directory, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
        _processes[scan_id] = proc
        for raw in proc.stdout:
            line = raw.rstrip()
            if not line:
                continue
            if line.startswith("PROGRESS "):
                try:
                    db.update_scan(scan_id, progress=min(0.99, max(0.0, float(line.split()[1]))))
                except ValueError:
                    pass
            else:
                log(line)
        code = proc.wait()
    except OSError as exc:
        log(f"ERROR could not start worker: {exc}")
        code = -1
    finally:
        _processes.pop(scan_id, None)

    if db.get_scan(scan_id, with_log=False) is None:  # deleted while running
        return
    if code != 0 or not output_path.exists():
        error = "Cancelled" if code in (-9, 137) else f"Worker exited with code {code}"
        log(f"ERROR {error}")
        db.update_scan(scan_id, status="failed", error=error, finished_at=db.now())
        return

    result = json.loads(output_path.read_text())
    findings = result.get("findings", [])
    if len(findings) > MAX_FINDINGS_PER_SCAN:
        findings.sort(key=lambda f: (db.SEVERITY_RANK.get(f.get("severity"), 9), -(f.get("score") or 0)))
        log(f"{len(findings):,} findings; keeping the {MAX_FINDINGS_PER_SCAN:,} most severe")
        findings = findings[:MAX_FINDINGS_PER_SCAN]
    db.insert_findings(scan_id, module.id, findings)
    log(f"Scan complete: {result.get('rows_scanned', 0):,} rows, {len(findings):,} findings stored")
    db.update_scan(scan_id, status="completed", progress=1.0, finished_at=db.now(),
                   rows_scanned=result.get("rows_scanned"))
