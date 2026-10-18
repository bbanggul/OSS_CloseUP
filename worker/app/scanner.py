"""Trivy/OSV subprocess boundary. No database access or package installation."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import time
from datetime import datetime, timezone
from uuid import uuid4


def _now():
    return datetime.now(timezone.utc).isoformat()


def _save(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def _execute(command, cwd, stdout_path, stderr_path, timeout):
    """Stream logs to disk and kill the process group on timeout (Linux/macOS)."""
    started = time.monotonic()
    result = {"command": command, "started_at": _now(), "exit_code": None,
              "timed_out": False, "error": None}
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            process = subprocess.Popen(command, cwd=cwd, stdout=stdout, stderr=stderr,
                                       start_new_session=True)
        except OSError as exc:
            result["error"] = {"kind": "launch_error", "message": str(exc)}
        else:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
                result["error"] = {"kind": "timeout", "message": f"Exceeded {timeout}s"}
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            result["exit_code"] = process.returncode
    result.update(finished_at=_now(), duration_seconds=round(time.monotonic() - started, 3),
                  stdout_path=str(stdout_path), stderr_path=str(stderr_path))
    return result


def _tool(name, binary, inputs, output, timeout):
    version = _execute([binary, "--version"], inputs,
                       output / f"{name}.version.stdout.log",
                       output / f"{name}.version.stderr.log", min(timeout, 10))
    version["text"] = Path(version["stdout_path"]).read_text(errors="replace").strip()
    if not version["text"]:
        version["text"] = Path(version["stderr_path"]).read_text(errors="replace").strip()
    raw = output / f"{name}.json"
    if name == "trivy":
        command = [binary, "fs", "--scanners", "vuln", "--format", "json",
                   "--output", str(raw), "--exit-code", "0", "--no-progress",
                   "--skip-version-check", "--disable-telemetry",
                   "--timeout", f"{timeout}s", str(inputs)]
    else:
        command = [binary, "scan", "source", "--lockfile", str(inputs / "package-lock.json"),
                   "--format", "json", "--output-file", str(raw)]
    result = _execute(command, inputs, output / f"{name}.stdout.log",
                      output / f"{name}.stderr.log", timeout)
    result.update(version=version, raw_output_path=str(raw), timeout_seconds=timeout)
    if result["error"] is None:
        accepted = (0,) if name == "trivy" else (0, 1)
        if result["exit_code"] not in accepted:
            result["error"] = {"kind": "tool_error", "message": f"Exit code {result['exit_code']}"}
        else:
            try:
                data = json.loads(raw.read_text(encoding="utf-8"))
                # An error object or empty file must never masquerade as a clean scan.
                if not isinstance(data, dict):
                    raise ValueError("Expected a JSON object")
                if name == "trivy":
                    if not isinstance(data.get("SchemaVersion"), int):
                        raise ValueError("Missing Trivy SchemaVersion")
                    if "Results" in data and not isinstance(data["Results"], (list, type(None))):
                        raise ValueError("Invalid Trivy Results")
                elif not isinstance(data.get("results"), list):
                    raise ValueError("Missing OSV results array")
            except (OSError, ValueError) as exc:
                result["error"] = {"kind": "invalid_output", "message": str(exc)}
    result["status"] = "completed" if result["error"] is None else "failed"
    return result


def run_scan(package_json, package_lock, output_dir, *, timeout_seconds=600,
             trivy_binary="trivy", osv_binary="osv-scanner"):
    """Return a JSON-serializable execution report; each attempt has a unique folder.

    Input errors raise ValueError before execution. Output/storage errors raise OSError.
    Tool errors are returned per tool, allowing the other scanner to continue.
    The report is an execution contract, not the future normalized Finding schema.
    """
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be finite and positive")
    snapshots = []
    for name, source in (("package.json", package_json), ("package-lock.json", package_lock)):
        source = Path(source).resolve()
        try:
            content = source.read_bytes()
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object")
            if name == "package-lock.json":
                lock_version = data.get("lockfileVersion")
                if type(lock_version) is not int or lock_version not in (1, 2, 3):
                    raise ValueError("Expected npm lockfileVersion 1, 2 or 3")
                field = "dependencies" if lock_version == 1 else "packages"
                if not isinstance(data.get(field), dict):
                    raise ValueError(f"Expected lockfile {field} object")
        except (OSError, ValueError, UnicodeError) as exc:
            raise ValueError(f"Invalid {name}: {exc}") from exc
        snapshots.append((name, source, content))

    attempt_id = uuid4().hex
    output = Path(output_dir).resolve() / attempt_id
    inputs = output / "inputs"
    inputs.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "attempt_id": attempt_id, "status": "running",
              "started_at": _now(), "finished_at": None, "inputs": {}, "tools": {},
              "manifest_path": str(output / "manifest.json")}
    for name, source, content in snapshots:
        target = inputs / name
        target.write_bytes(content)
        report["inputs"][name] = {"source_path": str(source), "snapshot_path": str(target),
                                  "sha256": hashlib.sha256(content).hexdigest()}
    _save(output / "manifest.json", report)
    for name, binary in (("trivy", trivy_binary), ("osv", osv_binary)):
        report["tools"][name] = _tool(name, str(binary), inputs, output, timeout_seconds)
        _save(output / "manifest.json", report)
    successes = sum(t["status"] == "completed" for t in report["tools"].values())
    report["status"] = {0: "failed", 1: "partial", 2: "completed"}[successes]
    report["finished_at"] = _now()
    _save(output / "manifest.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description="Run Trivy and OSV on npm input files")
    parser.add_argument("--package-json", required=True)
    parser.add_argument("--package-lock", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=600)
    args = parser.parse_args()
    try:
        report = run_scan(args.package_json, args.package_lock, args.output_dir,
                          timeout_seconds=args.timeout_seconds)
    except (ValueError, OSError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
