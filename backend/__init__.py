"""Reverse Engineer: REA (Reverse Engineer Anything) as a one-click Ducky plugin.

The panel points REA at a folder, a file or a running app and shows what it found;
agents get every REA tool through the nested `rea` MCP server this plugin registers.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import types
import uuid
from pathlib import Path

from . import runtime

INTENT = r"\b(rea|reverse[- ]engineer\w*|decompil\w*|disassembl\w*|binary analysis)\b"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
# Bigger results stay on disk and REA projects a summary of them (inspect-analysis-view).
_INLINE_MAX = 2 * 1024 * 1024
_DOC_DETAILS_MAX = 400 * 1024
# Per-source budget for analyze_javascript_application: big Electron apps need hours, so a run
# can go overnight. Hitting it is not a failure: REA keeps a partial observation (see _finish).
_JS_TIMEOUT_MS = 8 * 3600 * 1000
_PARTIAL_NOTE = "Stopped at the time limit; this shows everything it found up to then."

# Files REA has a dedicated reader for; anything else goes to inspect-artifact.
_BY_EXT = {
    ".gguf": "inspect-model-artifact", ".safetensors": "inspect-model-artifact",
    ".pyc": "inspect-python-pyc", ".beam": "inspect-erlang-beam", ".ips": "inspect-apple-ips",
    ".ko": "inspect-kernel-module", ".dtb": "inspect-devicetree",
}
SETUP_JOB_ID = "plugin:rea:setup"
RUN_JOB_PREFIX = "plugin:rea:run:"
REC_JOB_PREFIX = "plugin:rea:rec:"
# Plain words for the top bar's activity list (anything else: the command with spaces).
_CMD_LABEL = {
    "inspect-desktop-application": "Scanning the app", "inspect-artifact": "Reading the file",
    "analyze-javascript-application": "Reading its app code", "inspect-pe-imports": "Checking what it asks Windows for",
    "inspect-il2cpp-metadata": "Recovering Unity class names", "inspect-managed-artifact": "Reading its .NET code",
    "decompile": "Decompiling", "analyze": "Native overview",
}
_SUMMARY_CMDS = {"inspect-artifact", "inspect-desktop-application"}
# REA's inventory of a PE has no follow-ups of its own; these one-shot readers apply to any EXE/DLL.
_PE_PROBES = [
    ("inspect_pe_imports", "Which DLLs and functions it calls: the quickest map of what it does."),
    ("inspect_managed_artifact", "If it's .NET (C#, Unity Mono): its types, methods and IL."),
    ("inspect_pe_certificates", "Who signed it."),
    ("inspect_go_binary", "If it's written in Go: compiler, modules and build settings."),
    ("inspect_rust_binary", "If it's written in Rust: its crates and versions."),
]
# Once the native decompiler (Ghidra) is installed, any EXE/DLL also gets these.
_NATIVE_PROBES = [
    ("decompile", "Pseudocode of its entry function (Ghidra)."),
    ("analyze", "Native overview with Ghidra: functions, strings, imports and references."),
]
# Next probes that need an open REA session (MCP), not a one-shot CLI call.
_SESSION_OPS = {"open_binary"}
# Recreations: one subfolder each, in a folder the person can browse (and a Ducky project agents write to).
RECREATION_STATUSES = ("building", "done", "blocked", "stopped")
BRIEF_NAME = "REA-BRIEF.md"
_SCAN_SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "target", ".next"}


def recreations_root() -> Path:
    return Path.home() / "Documents" / "REA Recreations"


def _slug(name: str) -> str:
    s = re.sub(r"\s+", " ", re.sub(r"[^A-Za-z0-9 ._-]+", " ", str(name or ""))).strip(" .")
    return s[:60].rstrip(" .") or "Recreation"


def _unique_folder(root: Path, name: str) -> Path:
    base = _slug(name)
    for i in range(1, 1000):
        p = root / (base if i == 1 else f"{base} ({i})")
        if not p.exists():
            return p
    return root / f"{base} {uuid.uuid4().hex[:6]}"


def _scan(folder: Path, limit: int = 200) -> dict:
    """What an agent has written so far: file count, size, newest change and the first files."""
    files, count, size, newest = [], 0, 0, 0.0
    for base, dirs, names in os.walk(folder):
        dirs[:] = sorted(d for d in dirs if d not in _SCAN_SKIP)  # never descend into deps or build output
        for n in sorted(names):
            p = Path(base) / n
            try:
                st = p.stat()
            except OSError:
                continue
            count += 1
            size += st.st_size
            newest = max(newest, st.st_mtime)
            if len(files) < limit:
                files.append({"path": p.relative_to(folder).as_posix(), "bytes": st.st_size, "modified": int(st.st_mtime)})
    return {"file_count": count, "bytes": size, "last_change": int(newest), "files": files}


def _plan(path: Path) -> list[str]:
    if path.is_dir():
        return ["inspect-desktop-application"]
    name = path.name.lower()
    if name == "global-metadata.dat":
        return ["inspect-il2cpp-metadata"]
    cmd = _BY_EXT.get(path.suffix.lower(), "inspect-artifact")
    args = [cmd]
    if path.suffix.lower() == ".asar":
        args += ["--integrity-policy", "record-and-continue"]
    return args


def _digest(result: dict) -> dict:
    """The parts a person reads first: what it is, what runs it, where to look next."""
    top = result.get("summary") if isinstance(result.get("summary"), dict) else result
    nr = top.get("normalized_result") if isinstance(top.get("normalized_result"), dict) else {}
    inner = nr.get("summary") if isinstance(nr.get("summary"), dict) else nr
    counts = dict(inner.get("available_counts") or {})
    # A JavaScript/Electron summary: its statistics and Electron facts, non-zero numbers only.
    for key, src in (("", inner.get("statistics")), ("electron ", inner.get("electron")),
                     ("ipc ", (inner.get("electron") or {}).get("ipc"))):
        for k, v in (src or {}).items() if isinstance(src, dict) else ():
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v:
                counts[f"{key}{k}"] = v
    return {
        "evidence_id": top.get("evidence_id") or "",
        "parent_evidence_id": nr.get("parent_evidence_id") or "",
        "operation": nr.get("parent_operation") or top.get("operation") or "",
        "subject": top.get("subject") or {},
        "counts": counts,
        "coverage": inner.get("source_coverage") or nr.get("coverage") or {},
        "candidates": inner.get("candidates") or [],
        "components": inner.get("components") or [],
        "next_probes": inner.get("next_probe_groups") or [],
        "limitations": nr.get("limitations") or [],
        "unknowns": nr.get("unknowns") or [],
    }


def _partial_observation(path: Path) -> dict | None:
    """The Evidence REA kept when it hit its time limit (provider_timeout), or None."""
    try:
        doc = json.loads(path.read_text("utf-8", "replace"))
    except (OSError, ValueError, MemoryError):
        return None
    obs = (doc.get("details") or {}).get("partial_observation") if isinstance(doc, dict) else None
    return obs if isinstance(obs, dict) and obs.get("evidence_id") else None


def _error_head(path: Path) -> dict:
    """A big failed result still starts with REA's error: code, message, remediation."""
    try:
        with open(path, "rb") as f:
            head = f.read(16384).decode("utf-8", "replace")
    except OSError:
        return {}
    out: dict = {}
    for key in ("error", "code", "message"):
        m = re.search(rf'"{key}":"((?:[^"\\]|\\.)*)"', head)
        if m:
            out[key] = json.loads(f'"{m[1]}"')
    m = re.search(r'"remediation":\{"action":"((?:[^"\\]|\\.)*)"', head)
    if m:
        out["remediation"] = {"action": json.loads(f'"{m[1]}"')}
    return out


def register(api) -> None:
    data = api.data
    pid = api.plugin_id
    state = {"busy": False, "step": "", "percent": None, "error": "", "cancelled": False, "log": []}
    lock = threading.Lock()
    cancel = threading.Event()

    def _push(kind: str, **extra) -> None:
        try:
            from frontend.ui_web.verse_editor.panel_events import push_agent_event

            push_agent_event({"type": f"rea_{kind}", **extra})
        except Exception:  # noqa: BLE001 — no panel host in tests
            pass

    def _job(phase: str, detail: str, percent=None) -> None:
        """The setup's row in the header's activity list (Cancel there calls cancel_job)."""
        try:
            from frontend.ui_web.agent_modes import push_ui_event

            push_ui_event({"type": "background_job", "id": SETUP_JOB_ID, "source": "plugin",
                           "title": "Reverse Engineer setup", "detail": detail, "percent": percent,
                           "phase": phase, "cancelable": phase == "working"})
        except Exception:  # noqa: BLE001
            pass

    def _log(msg: str, percent=None) -> None:
        changed = msg != state["step"]
        state["step"], state["percent"] = msg, percent
        if changed:
            state["log"] = (state["log"] + [msg])[-30:]
            api.log(msg)
        _push("status", step=msg, percent=percent)
        _job("working", msg, percent)

    def _alert(status_line: str, level: str) -> None:
        try:
            from frontend.notifications import alert

            alert("Reverse Engineer", status_line, level=level)
        except Exception:  # noqa: BLE001
            pass

    def _runs_dir() -> Path:
        return Path(api.local_dir("runs"))

    def _marker() -> Path:
        return runtime.root() / "mcp_registered.json"

    def _write_marker() -> None:
        try:
            _marker().write_text(json.dumps(_mcp_config(), sort_keys=True), "utf-8")
        except OSError:
            pass

    # ---- runtime -----------------------------------------------------------------

    def _mcp_config() -> dict:
        command, args = runtime.mcp_command()
        return {
            "transport": "stdio", "command": command, "args": args,
            # 6.8.0 takes only full|off here ("compact" makes it exit); off keeps tools/list small.
            "env": {"REA_MCP_OUTPUT_SCHEMA_PROFILE": "off", **runtime.provider_env()},
            "label": "REA (Reverse Engineer Anything)",
            "description": "Reverse engineer binaries, apps, archives, websites and captures: "
                           "229 tools with evidence. Set up by the Reverse Engineer plugin.",
            "tool_prefix": "rea",
            "intents": ["reverse engineer", "reverse-engineer", "decompile", "disassemble", "rea"],
        }

    def _register_mcp() -> dict:
        try:
            out = api.call_tool("ducky_mcp_upsert_server", {"id": "rea", "config": _mcp_config()})
            try:
                # Off then on: an upsert alone keeps a session started with the old config.
                api.call_tool("ducky_mcp_set_plugin", {"plugin_id": "rea", "enabled": False})
                api.call_tool("ducky_mcp_set_plugin", {"plugin_id": "rea", "enabled": True})
            except Exception as exc:  # noqa: BLE001
                api.log(f"enable rea MCP: {exc}")
            return {"ok": True, "result": out}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

    def status() -> dict:
        return {
            "ok": True, "ready": runtime.ready(), "version": runtime.installed_version(),
            "pinned": runtime.REA_VERSION, "node": runtime.NODE_VERSION,
            "ghidra": runtime.ghidra_ready(), "ghidra_version": runtime.GHIDRA_VERSION,
            "jdk_version": runtime.JDK_VERSION,
            "busy": state["busy"], "step": state["step"], "percent": state["percent"],
            "error": state["error"], "cancelled": state["cancelled"],
            "log": state["log"][-8:], "runtime_folder": str(runtime.root()),
        }

    def _setup_job(update: bool, ghidra: bool) -> None:
        try:
            runtime.setup(_log, cancel, update=update)
            if ghidra:
                runtime.ensure_ghidra(_log, cancel)
                _log("Checking the native decompiler…", 99)
                healthy, detail = runtime.doctor_ghidra()
                if not healthy:
                    raise RuntimeError(f"Ghidra installed but REA can't use it: {detail}")
            _log("Giving your agents REA's tools…", 99)
            reg = _register_mcp()
            if reg.get("ok"):
                _write_marker()
            done = (f"Native decompiler ready (Ghidra {runtime.GHIDRA_VERSION}). Point it at any EXE or DLL."
                    if ghidra else f"REA {runtime.installed_version()} is ready. Point it at any folder or file.")
            state.update(error="", step=done, percent=100)
            _job("done", done, 100)
            _alert("Native decompiler is ready." if ghidra else "REA is ready.", "ok")
        except runtime.Cancelled:
            state.update(cancelled=True, error="", step="Setup cancelled.", percent=None)
            _job("error", "Cancelled. Open Reverse Engineer to start it again.")
        except Exception as exc:  # noqa: BLE001
            state["error"] = str(exc)[-1200:]
            state["step"] = "Setup failed."
            _job("error", f"Setup failed: {state['error'][:200]}")
            _alert("REA setup failed.", "error")
        finally:
            state["busy"] = False
            _push("status", done=True)

    def setup(update: bool = False, wait: bool = False, ghidra: bool = False) -> dict:
        with lock:
            if state["busy"]:
                return {**status(), "started": False}
            if runtime.ready() and not update and (not ghidra or runtime.ghidra_ready()):
                reg = _register_mcp()
                return {**status(), "started": False, "mcp": reg}
            cancel.clear()
            state.update(busy=True, error="", cancelled=False, log=[], percent=0)
        _log("Adding the native decompiler…" if ghidra else "Starting REA setup…", 0)
        t = threading.Thread(target=_setup_job, args=(bool(update), bool(ghidra)), name="rea-setup", daemon=True)
        t.start()
        if wait:
            t.join(timeout=1500)
        return {**status(), "started": True}

    def cancel_job(job_id: str = "") -> dict:
        """Cancel the setup, one run (``plugin:rea:run:<id>`` or its id), or with no id the setup or newest run."""
        jid = str(job_id or "").strip()
        if jid.startswith(RUN_JOB_PREFIX):
            return cancel_run(jid[len(RUN_JOB_PREFIX):])
        if jid.startswith(REC_JOB_PREFIX):  # Stop on a recreation's row: mark it stopped (its chat keeps its history)
            return recreation_update(jid[len(REC_JOB_PREFIX):], "Stopped from the top bar.", "stopped")
        if jid and jid != SETUP_JOB_ID:
            return cancel_run(jid)
        if state["busy"]:
            cancel.set()
            return {**status(), "cancelling": True}
        if not jid and runs_live:
            return cancel_run(sorted(runs_live)[-1])
        return {**status(), "cancelled": False, "note": "Nothing is running."}

    # ---- runs --------------------------------------------------------------------

    # run id -> its cancel. Kept outside this module so a plugin update or reinstall mid-run (same
    # app process, the run's thread keeps going) still shows the run as running and can cancel it.
    runs_live: dict[str, threading.Event] = sys.modules.setdefault(
        "_ducky_rea_runs_live", types.ModuleType("_ducky_rea_runs_live")).__dict__.setdefault("runs", {})

    def _put_run(doc: dict) -> dict:
        data.put(f"run.{doc['id']}", doc)
        try:
            subj = (doc.get("digest") or {}).get("subject") or {}
            api.search.upsert(doc["id"], doc["name"], f"{doc['target']} {subj.get('format', '')} {doc['command']}")
        except Exception:  # noqa: BLE001
            pass
        _push("runs_changed", id=doc["id"])
        return doc

    def _run_row(doc: dict, step: str = "", percent=None) -> None:
        status = doc.get("status") or "cancelled"  # runs saved by early versions have no status
        cmd = doc.get("command") or ""
        phase = {"running": "working", "done": "done", "partial": "done"}.get(status, "error")
        label = _CMD_LABEL.get(cmd, cmd.replace("-", " ").capitalize())
        if status == "running":
            detail = f"{label}{f' · {percent}%' if isinstance(percent, (int, float)) else ''} · {step or 'starting…'}"
        else:
            detail = {"done": f"{label}: done in {doc.get('seconds', 0)} s. Open Reverse Engineer for the results.",
                      "partial": _PARTIAL_NOTE, "cancelled": "Cancelled."}.get(status, (doc.get("error") or "")[:200])
        try:
            from frontend.ui_web.agent_modes import push_ui_event

            push_ui_event({"type": "background_job", "id": f"{RUN_JOB_PREFIX}{doc['id']}", "source": "plugin",
                           "title": f"REA · {Path(doc.get('target') or '').name or doc.get('target') or doc['id']}", "detail": detail, "percent": percent,
                           "phase": phase, "cancelable": phase == "working"})
        except Exception:  # noqa: BLE001
            pass

    def _finish(doc: dict, args: list[str], stop: threading.Event, hard_timeout_s: float) -> None:
        target, cmd = doc["target"], doc["command"]
        folder = _runs_dir() / doc["id"]
        out_path, evidence = folder / "result.json", folder / "evidence.json"
        started = time.time()
        try:
            while True:
                full = [cmd, target, *args[1:], "--json"]
                if cmd in _SUMMARY_CMDS:
                    full += ["--detail", "summary", "--evidence_output", str(evidence)]
                evidence.unlink(missing_ok=True)
                def heard(step: str, percent) -> None:
                    doc["step"], doc["percent"] = step, percent
                    _run_row(doc, step, percent)
                    _push("run_progress", id=doc["id"], step=step, percent=percent)

                code, err = runtime.run(full, out_path, stop, timeout=hard_timeout_s, on_progress=heard)
                size = out_path.stat().st_size if out_path.is_file() else 0
                result: dict = {}
                if 0 < size <= _INLINE_MAX:
                    try:
                        result = json.loads(out_path.read_text("utf-8", "replace"))
                    except ValueError:
                        result = {}
                elif size and code != 0:
                    result = _error_head(out_path)
                # An archive whose declared integrity doesn't match its files: keep going, marked untrusted.
                if result.get("code") == "artifact_integrity_mismatch" and "--integrity-policy" not in args:
                    args = [cmd, "--integrity-policy", "record-and-continue", *args[1:]]
                    continue
                break
            failed = code != 0 or ("error" in result and "evidence_id" not in result and "summary" not in result)
            digest = _digest(result) if result and not failed else {}
            if digest and not digest["next_probes"] and (digest["subject"] or {}).get("format") == "pe":
                pe_probes = _PE_PROBES + (_NATIVE_PROBES if runtime.ghidra_ready() else [])
                digest["next_probes"] = [{"operation": op, "count": 1, "example": {"operation": op, "path": target, "rationale": why}}
                                         for op, why in pe_probes if op.replace("_", "-") != cmd]
            project_from = out_path if size > _INLINE_MAX and code == 0 else None
            partial = False
            if failed and result.get("code") == "provider_timeout":
                # Out of time, not broken: summarize the Evidence REA observed before the deadline.
                obs = _partial_observation(out_path)
                if obs:
                    project_from = folder / "partial.json"
                    project_from.write_text(json.dumps(obs), "utf-8")
                    partial = True
            if project_from is not None:
                # Too big to read here: REA projects a summary from the saved Evidence file.
                view_req = folder / "summary-request.json"
                view_req.write_text(json.dumps({"source": {"kind": "evidence-file", "path": str(project_from)},
                                                "view": {"kind": "summary"}}), "utf-8")
                summary_path = folder / "summary.json"
                heard("Summarizing the result…", None)
                vcode, verr = runtime.run(["inspect-analysis-view", str(view_req), "--json"], summary_path, stop)
                try:
                    projected = json.loads(summary_path.read_text("utf-8", "replace")) if vcode == 0 else {}
                except (OSError, ValueError):
                    projected = {}
                failed = not projected
                err = err if projected else (verr or err)
                result = projected
                digest = _digest(projected) if projected else {}
            doc.update(
                status="error" if failed else "partial" if partial else "done", ok=not failed, args=full,
                note=_PARTIAL_NOTE if partial and not failed else "",
                error=(result.get("message") or err.strip()[-600:] or f"REA exited {code}") if failed else "",
                remediation=(result.get("remediation") or {}).get("action", "") if failed else "",
                digest=digest, result_bytes=size, evidence_path=str(evidence) if evidence.is_file() else "",
            )
            if result and not failed and len(json.dumps(result)) <= _DOC_DETAILS_MAX:
                doc["details"] = result
        except runtime.Cancelled:
            doc.update(status="cancelled", ok=False, error="Cancelled.")
        except Exception as exc:  # noqa: BLE001
            doc.update(status="error", ok=False, error=str(exc)[-600:])
        finally:
            runs_live.pop(doc["id"], None)
        doc["seconds"] = round(time.time() - started, 1)
        doc.pop("step", None)
        doc.pop("percent", None)
        _put_run(doc)
        _run_row(doc)
        if doc["seconds"] >= 20 and doc["status"] in ("done", "error"):
            _alert(f"{doc['name']}: {'done' if doc['ok'] else 'failed'}.", "ok" if doc["ok"] else "error")

    def _start(target: str, args: list[str], wait_s: float, hard_timeout_s: float = 9 * 3600) -> dict:
        """Start one REA run in the background; wait up to ``wait_s`` for it."""
        run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        cmd = args[0]
        doc = {
            "id": run_id, "name": f"{Path(target).name or target} · {cmd.replace('inspect-', '').replace('-', ' ')}",
            "target": target, "command": cmd, "args": [], "created": int(time.time()), "seconds": 0,
            "status": "running", "ok": None, "error": "", "remediation": "", "digest": {},
            "result_path": str(_runs_dir() / run_id / "result.json"), "result_bytes": 0, "evidence_path": "",
        }
        _put_run(doc)
        api.changeset.record(command="rea_analyze", kind="run", ident=run_id, facet="record", before=None,
                             inverse=[{"command": "rea_delete", "params": {"run_id": run_id}}],
                             slot=f"{pid}://run/{run_id}/record")
        stop = threading.Event()
        runs_live[run_id] = stop
        _run_row(doc)
        t = threading.Thread(target=_finish, args=(doc, list(args), stop, hard_timeout_s), name=f"rea-run-{run_id}", daemon=True)
        t.start()
        if wait_s > 0:
            t.join(timeout=wait_s)
        return dict(data.get(f"run.{run_id}") or doc)

    def _answer(doc: dict) -> dict:
        slim = _slim(doc)
        if doc.get("status") == "running":
            return {"ok": True, "running": True, "run": slim,
                    "note": "Still running in the background (top bar's activity list). rea_get(run_id) shows it when done."}
        return {"ok": bool(doc.get("ok")), "run": slim, "error": doc.get("error", "")}

    def analyze(target: str = "", wait_s: float = 150) -> dict:
        t = str(target or "").strip().strip('"').strip()
        if not t:
            return {"ok": False, "error": "Point at something: a folder, a file, or a running app."}
        if re.match(r"^https?://", t, re.I):
            return {"ok": False, "website": True,
                    "error": "Websites need a live browser session: use Investigate (an agent drives REA's web tools)."}
        path = Path(t)
        if not path.exists():
            return {"ok": False, "error": f"Nothing at {t}."}
        if not runtime.ready():
            return {"ok": False, "error": "REA is still getting ready: watch the top bar's activity list."}
        return _answer(_start(str(path.resolve()), _plan(path), float(wait_s or 0)))

    def probe(operation: str = "", path: str = "", wait_s: float = 150, time_limit_min: float = 0) -> dict:
        op = str(operation or "").strip()
        if not re.fullmatch(r"[a-z][a-z0-9_]{2,80}", op):
            return {"ok": False, "error": "operation must be a REA operation such as inspect_pe_imports."}
        if op in _SESSION_OPS:
            return {"ok": False, "error": f"{op} needs a REA session: use Investigate."}
        if not path or not Path(path).exists():
            return {"ok": False, "error": f"Nothing at {path!r}."}
        if not runtime.ready():
            return {"ok": False, "error": "REA is still getting ready: watch the top bar's activity list."}
        args = [op.replace("_", "-")]
        if op in ("decompile", "analyze", "function", "xrefs") and not runtime.ghidra_ready():
            return {"ok": False, "needs_ghidra": True,
                    "error": "Native decompiling needs Ghidra: rea_setup(ghidra=true) adds it in one click."}
        if op == "decompile":
            args += ["--procedure", "entry"]
        if Path(path).suffix.lower() == ".asar":
            args += ["--integrity-policy", "record-and-continue"]
        budget_ms = int(min(24 * 60, max(0.1, float(time_limit_min))) * 60000) if time_limit_min else _JS_TIMEOUT_MS
        if op == "analyze_javascript_application":
            # REA's 5 min per source is too short for big bundles; this runs in the background with Cancel.
            args += ["--analysis-timeout-ms", str(budget_ms), "--max-heap-mb", "4096"]
        # The hard stop sits past REA's own budget so REA, not a kill, ends the run (and keeps a partial).
        return _answer(_start(str(Path(path).resolve()), args, float(wait_s or 0), budget_ms / 1000 + 3600))

    def cancel_run(run_id: str) -> dict:
        stop = runs_live.get(run_id)
        if stop is not None:
            stop.set()
            return {"ok": True, "cancelling": run_id}
        # Not ours any more (started by an older copy of the plugin, or its thread is gone): its REA
        # process may still be working. Find it by command line, stop it, and close its row either way.
        doc = data.get(f"run.{run_id}")
        if not doc:
            _run_row({"id": run_id, "target": run_id, "command": "", "status": "cancelled"})
            return {"ok": True, "cancelled": run_id, "note": "No such run; its row is closed."}
        target, cmd = doc.get("target") or "", doc.get("command") or ""
        busy_elsewhere = any((data.get(f"run.{rid}") or {}).get("target") == target
                             and (data.get(f"run.{rid}") or {}).get("command") == cmd for rid in runs_live)
        killed = [] if busy_elsewhere else runtime.kill_matching(cmd, target)
        if doc.get("status") in (None, "running"):
            doc.update(status="cancelled", ok=False, error="Cancelled.")
            doc.pop("step", None)
            doc.pop("percent", None)
            _put_run(doc)
        _run_row(doc)
        return {"ok": True, "cancelled": run_id, "stopped_processes": killed}

    def _slim(doc: dict) -> dict:
        return {k: v for k, v in doc.items() if k != "details"}

    def _live(doc: dict) -> dict:
        # A run left "running" by a closed app never finishes: show it as stopped.
        if doc.get("status") == "running" and doc.get("id") not in runs_live:
            return {**doc, "status": "error", "ok": False, "error": "Stopped when Ducky closed. Run it again."}
        return doc

    def list_runs(limit: int = 50) -> dict:
        rows = sorted(data.items("run.").values(), key=lambda d: d.get("created", 0), reverse=True)
        return {"ok": True, "runs": [_slim(_live(r)) for r in rows[: max(1, int(limit or 50))]], "count": len(rows)}

    def get_run(run_id: str = "") -> dict:
        doc = data.get(f"run.{run_id}") if run_id else None
        if not doc:
            return {"ok": False, "error": f"No run {run_id!r}."}
        return {"ok": True, "run": _live(doc)}

    def delete_run(run_id: str = "") -> dict:
        doc = data.get(f"run.{run_id}") if run_id else None
        if not doc:
            return {"ok": False, "error": f"No run {run_id!r}."}
        if run_id in runs_live:
            runs_live[run_id].set()
        data.delete(f"run.{run_id}")
        shutil.rmtree(_runs_dir() / run_id, ignore_errors=True)
        try:
            api.search.delete(run_id)
        except Exception:  # noqa: BLE001
            pass
        api.changeset.record(command="rea_delete", kind="run", ident=run_id, facet="record", before=doc,
                             inverse=[], slot=f"{pid}://run/{run_id}/record")
        _push("runs_changed", id=run_id)
        return {"ok": True, "id": run_id}

    def running_apps() -> dict:
        """Windows with a title and an executable: point at one to inspect its install folder."""
        if sys.platform != "win32":
            return {"ok": False, "error": "Listing running apps works on Windows only."}
        ps = ("Get-Process | Where-Object { $_.MainWindowTitle -and $_.Path } | "
              "Select-Object Id,ProcessName,MainWindowTitle,Path | ConvertTo-Json -Compress")
        try:
            proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                                  capture_output=True, text=True, encoding="utf-8", errors="replace",
                                  timeout=30, creationflags=_NO_WINDOW, stdin=subprocess.DEVNULL)
            rows = json.loads(proc.stdout or "[]")
        except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
            return {"ok": False, "error": f"Couldn't list running apps: {exc}"}
        rows = [rows] if isinstance(rows, dict) else rows
        apps = [{"pid": r.get("Id"), "name": r.get("ProcessName"), "title": r.get("MainWindowTitle"),
                 "exe": r.get("Path"), "folder": str(Path(r.get("Path") or "").parent)} for r in rows or []]
        apps.sort(key=lambda a: str(a["name"]).lower())
        return {"ok": True, "apps": apps}

    def investigate(target: str = "", question: str = "", run_id: str = "") -> dict:
        t = str(target or "").strip()
        doc = data.get(f"run.{run_id}") if run_id else None
        if not t and doc:
            t = doc.get("target", "")
        if not t:
            return {"ok": False, "error": "Say what to investigate: a path, an app or a website."}
        q = str(question or "").strip() or "How does it work? What is it built with, and where is its interesting logic?"
        lines = [
            f"Reverse engineer this with REA (the rea__* tools; find them with ducky_get_tools('rea')): {t}",
            f"Question: {q}",
            "Show the evidence behind each finding and say what stays unknown.",
            "Slow work (analyze_javascript_application, big folders): call rea_probe(operation, path) or "
            "rea_analyze(target) instead of the rea__ tool; they run in the background past a tool's time "
            "limit; then rea_get(run_id). Read a saved result file with rea__inspect_analysis_view "
            "{source: {kind: 'evidence-file', path: <result_path>}, view: {kind: 'summary'}} "
            "(REA reads it; your file tools can't open AppData).",
        ]
        if doc and doc.get("ok"):
            d = doc.get("digest") or {}
            lines.append(f"A first pass already ran ({doc.get('command')}); its full result is at "
                         f"{doc.get('result_path')}" + (f", evidence bundle {doc['evidence_path']}" if doc.get("evidence_path") else "")
                         + f". Candidates: {json.dumps(d.get('candidates') or [])[:1500]}")
        if not runtime.ready():
            lines.append("REA isn't set up yet: call rea_setup(wait=true) first.")
        out = _open_chat(f"Reverse engineer {Path(t).name or t}", "\n".join(lines), navigate=True)
        return {**out, "message": "\n".join(lines)} if out.get("ok") else out

    def _first_id(res) -> str:
        res = res or {}
        return str(res.get("conv_id") or res.get("group_id") or res.get("id")
                   or (res.get("chat") or {}).get("id") or (res.get("group") or {}).get("id") or "")

    def _chat_group() -> str:
        """The 'REA Recreations' chat group every recreation chat goes in (made once, then remembered)."""
        mark = Path(api.local_dir("state")) / "chat_group.json"
        try:
            gid = json.loads(mark.read_text("utf-8")).get("id", "")
            if gid:
                return gid
        except (OSError, ValueError):
            pass
        try:
            gid = _first_id(api.call_tool("ducky_create_folder", {"name": "REA Recreations"}))
        except Exception as exc:  # noqa: BLE001
            api.log(f"REA Recreations chat group: {exc}")
            return ""
        if gid:
            mark.parent.mkdir(parents=True, exist_ok=True)
            mark.write_text(json.dumps({"id": gid}), "utf-8")
        return gid

    def _open_chat(title: str, message: str, folder_id: str = "", navigate: bool = False) -> dict:
        try:
            args = {"title": title[:60], **({"folder_id": folder_id} if folder_id else {})}
            conv = _first_id(api.call_tool("ducky_create_chat", args))
            if not conv and folder_id:  # the group went away: fall back to the sidebar root
                conv = _first_id(api.call_tool("ducky_create_chat", {"title": title[:60]}))
            if not conv:
                return {"ok": False, "error": "Couldn't open a chat."}
            api.call_tool("ducky_send_chat_message", {"conv_id": conv, "message": message, "wait_for_reply": False})
            if navigate:
                try:
                    api.call_tool("ducky_ui_navigate", {"route": "chat", "item_id": conv})
                except Exception:  # noqa: BLE001
                    pass
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "conv_id": conv}

    # ---- recreations -----------------------------------------------------------------

    def _rec_row(doc: dict) -> None:
        """A recreation's row in the top bar's activity list: its newest milestone, live, tab open or not."""
        phase = {"building": "working", "done": "done"}.get(doc["status"], "error")
        last = ((doc.get("notes") or [{}])[-1]).get("text", "")
        detail = {"done": f"Done. {last}", "stopped": "Stopped.", "blocked": f"Blocked: {last}"}.get(doc["status"], last)
        try:
            from frontend.ui_web.agent_modes import push_ui_event

            push_ui_event({"type": "background_job", "id": f"{REC_JOB_PREFIX}{doc['id']}", "source": "plugin",
                           "title": f"Recreating · {doc['name'].removesuffix(' recreation')}"
                                    f"{' (team)' if doc.get('mode') == 'team' else ''}",
                           "detail": detail[:200], "percent": doc.get("percent"),
                           "phase": phase, "cancelable": phase == "working"})
        except Exception:  # noqa: BLE001 — no app host in tests
            pass

    def _put_rec(doc: dict) -> dict:
        data.put(f"recreation.{doc['id']}", doc)
        _rec_row(doc)
        try:
            api.search.upsert(doc["id"], doc["name"], f"recreation {doc['goal']} {doc['target']}")
        except Exception:  # noqa: BLE001
            pass
        _push("recreations_changed", id=doc["id"])
        return doc

    def _rec_view(doc: dict, files: bool = False) -> dict:
        scan = _scan(Path(doc["folder"]), 200 if files else 0)
        if not files:
            scan.pop("files", None)
        return {**doc, **scan, "folder_exists": Path(doc["folder"]).is_dir()}

    def recreate(run_id: str = "", goal: str = "", mode: str = "solo", target: str = "") -> dict:
        run = data.get(f"run.{run_id}") if run_id else None
        t = str(target or (run or {}).get("target") or "").strip()
        if not t:
            return {"ok": False, "error": "Say what to recreate: pick an analysis (run_id) or a target path."}
        mode = "team" if str(mode).lower() == "team" else "solo"
        what = str(goal or "").strip() or "A working recreation of its main features and look."
        name = Path(t).name or t
        folder = _unique_folder(recreations_root(), name)
        try:
            folder.mkdir(parents=True)
        except OSError as exc:
            return {"ok": False, "error": f"Couldn't make the folder {folder}: {exc}"}
        rec_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        d = (run or {}).get("digest") or {}
        brief = [f"# Recreate: {name}", "", f"- **Original:** `{t}`", f"- **Goal:** {what}",
                 f"- **Mode:** {'Team of agents' if mode == 'team' else 'One agent'}", f"- **Recreation id:** `{rec_id}`"]
        if run:
            brief += [f"- **REA analysis:** `{run_id}` (full result: `{run.get('result_path', '')}`)", "",
                      "## What REA found", "```json", json.dumps({k: d.get(k) for k in ("subject", "candidates", "counts")}, indent=2)[:6000], "```"]
        (folder / BRIEF_NAME).write_text("\n".join(brief) + "\n", "utf-8")
        doc = {"id": rec_id, "name": f"{name} recreation", "target": t, "goal": what, "mode": mode,
               "run_id": run_id if run else "", "folder": str(folder), "conv_id": "", "status": "building",
               "created": int(time.time()), "updated": int(time.time()),
               "notes": [{"t": int(time.time()), "text": "Folder made, brief written. Agent starting…"}]}
        _put_rec(doc)
        api.changeset.record(command="rea_recreate", kind="recreation", ident=rec_id, facet="record", before=None,
                             inverse=[{"command": "rea_recreation_delete", "params": {"recreation_id": rec_id}}],
                             slot=f"{pid}://recreation/{rec_id}/record")
        lines = [
            f"Recreate {name} from its REA reverse engineering. Recreation id: {rec_id}.",
            f"Goal: {what}",
            f"Work ONLY inside this folder (it's yours): {folder}",
            f"Start by reading {folder / BRIEF_NAME}. Dig deeper with REA: "
            + (f"rea_get('{run_id}'), " if run else "") + "rea_probe / rea_analyze, and the rea__* tools "
            "(ducky_get_tools('rea')). Read big result files with rea__inspect_analysis_view.",
            "Rebuild it as original code: match what it does and how it looks; never copy its binaries, assets or "
            "proprietary code. Keep README.md in the folder current: what it is and how to run it.",
            f"Report each milestone with rea_recreation_update(recreation_id='{rec_id}', note='<what just happened>', "
            "percent=<0-100>) so the person sees it live in the Reverse Engineer panel. At the end call it with "
            "status='done' (or status='blocked' and the reason).",
        ]
        if mode == "team":
            lines.append("Work as a team: write the plan with ducky_create_plan (research with REA, core logic, UI, "
                         "tests, one sub plan each with its own subfolder of the recreation folder as its Files), "
                         "then seat it with ONE ducky_swarm_create(from_plan=true) call. You lead and review; "
                         "members report milestones with rea_recreation_update too.")
        out = _open_chat(f"Recreate {name}", "\n".join(lines), folder_id=_chat_group())
        if not out.get("ok"):
            doc.update(status="blocked", notes=doc["notes"] + [{"t": int(time.time()), "text": out.get("error", "")}])
            _put_rec(doc)
            return {"ok": False, "error": out.get("error"), "recreation": _rec_view(doc)}
        doc["conv_id"] = out["conv_id"]
        _put_rec(doc)
        return {"ok": True, "recreation": _rec_view(doc)}

    rec_lock = threading.Lock()

    def recreation_update(recreation_id: str = "", note: str = "", status: str = "", percent=None) -> dict:
        if status and status not in RECREATION_STATUSES:
            return {"ok": False, "error": f"status must be one of {', '.join(RECREATION_STATUSES)}."}
        # ponytail: one lock per app process; team members updating at once append in turn.
        with rec_lock:
            return _recreation_update(recreation_id, note, status, percent)

    def _recreation_update(recreation_id: str, note: str, status: str, percent) -> dict:
        doc = data.get(f"recreation.{recreation_id}") if recreation_id else None
        if not doc:
            return {"ok": False, "error": f"No recreation {recreation_id!r}."}
        if status:
            doc["status"] = status
        if percent not in (None, ""):
            doc["percent"] = max(0, min(100, int(float(percent))))
        if status == "done":
            doc["percent"] = 100
        if note:
            doc["notes"] = (doc.get("notes") or []) + [{"t": int(time.time()), "text": str(note)[:500]}]
            doc["notes"] = doc["notes"][-50:]
        doc["updated"] = int(time.time())
        _put_rec(doc)
        if status in ("done", "blocked"):
            _alert(f"{doc['name']}: {status}.", "ok" if status == "done" else "error")
        return {"ok": True, "recreation": _rec_view(doc)}

    def list_recreations() -> dict:
        rows = sorted(data.items("recreation.").values(), key=lambda d: d.get("created", 0), reverse=True)
        return {"ok": True, "root": str(recreations_root()), "recreations": [_rec_view(r) for r in rows]}

    def get_recreation(recreation_id: str = "") -> dict:
        doc = data.get(f"recreation.{recreation_id}") if recreation_id else None
        if not doc:
            return {"ok": False, "error": f"No recreation {recreation_id!r}."}
        return {"ok": True, "recreation": _rec_view(doc, files=True)}

    def delete_recreation(recreation_id: str = "", delete_files: bool = False) -> dict:
        doc = data.get(f"recreation.{recreation_id}") if recreation_id else None
        if not doc:
            return {"ok": False, "error": f"No recreation {recreation_id!r}."}
        folder = Path(doc["folder"])
        if delete_files and folder.is_dir() and recreations_root() in folder.resolve().parents:
            shutil.rmtree(folder, ignore_errors=True)
        data.delete(f"recreation.{recreation_id}")
        try:
            api.search.delete(recreation_id)
        except Exception:  # noqa: BLE001
            pass
        api.changeset.record(command="rea_recreation_delete", kind="recreation", ident=recreation_id, facet="record",
                             before=doc, inverse=[], slot=f"{pid}://recreation/{recreation_id}/record")
        _push("recreations_changed", id=recreation_id)
        return {"ok": True, "id": recreation_id, "files_deleted": bool(delete_files)}

    def open_recreation(recreation_id: str = "", what: str = "folder") -> dict:
        doc = data.get(f"recreation.{recreation_id}") if recreation_id else None
        if what == "root" or not doc:
            if what != "root":
                return {"ok": False, "error": f"No recreation {recreation_id!r}."}
            folder = recreations_root()
            folder.mkdir(parents=True, exist_ok=True)
        elif what == "chat":
            if not doc.get("conv_id"):
                return {"ok": False, "error": "This recreation has no chat."}
            api.call_tool("ducky_ui_navigate", {"route": "chat", "item_id": doc["conv_id"]})
            return {"ok": True, "conv_id": doc["conv_id"]}
        else:
            folder = Path(doc["folder"])
        if not folder.is_dir():
            return {"ok": False, "error": f"The folder is gone: {folder}"}
        if sys.platform == "win32":
            os.startfile(str(folder))  # noqa: S606 — opens Explorer on the person's own folder
        return {"ok": True, "folder": str(folder)}

    # ---- MCP tools ---------------------------------------------------------------

    @api.tool(intent=INTENT, listener=False)
    def rea_status() -> dict:
        """Is REA set up on this PC (its own Node + rea-agents), which version, and setup progress."""
        return status()

    @api.tool(intent=INTENT, listener=False)
    def rea_setup(update: bool = False, wait: bool = False, ghidra: bool = False) -> dict:
        """One-click install of REA: a pinned, SHA-checked Node and rea-agents, then registers REA's 229
        tools for agents as the nested `rea` MCP server. update=true installs the newest REA;
        ghidra=true also adds the native decompiler (Ghidra 12.1.4 + JDK 21, ~650 MB) for pseudocode
        and xrefs on EXEs/DLLs; wait=true blocks until done (a few minutes the first time)."""
        return setup(update, wait, ghidra)

    @api.tool(intent=INTENT, listener=False)
    def rea_cancel_job(job_id: str = "") -> dict:
        """Cancel the REA setup or a running analysis (job_id = a run id; empty = the setup or newest run)."""
        return cancel_job(job_id)

    @api.tool(intent=INTENT, listener=False)
    def rea_analyze(target: str, wait_s: float = 150) -> dict:
        """Point REA at anything on this PC: an install folder (finds the runtime: Unity, Unreal, Electron,
        .NET, Godot…), an EXE/DLL, an .asar, a game pack, a model file. Returns what it is, its candidates
        and next probes, and saves the run. Runs in the background; past wait_s it returns running=true
        (rea_get(run_id) later)."""
        return analyze(target, wait_s)

    @api.tool(intent=INTENT, listener=False)
    def rea_probe(operation: str, path: str, wait_s: float = 150, time_limit_min: float = 0) -> dict:
        """Run one follow-up REA operation from a run's next probes (e.g. inspect_pe_imports,
        analyze_javascript_application, inspect_il2cpp_metadata) on one path. Background like rea_analyze.
        analyze_javascript_application may run for hours on a big app; if it hits its time limit the run
        ends status=partial with a summary of everything found so far. time_limit_min sets that limit
        (default 480 = 8 h, at most 1440): a short one for a quick look, a long one to run overnight."""
        return probe(operation, path, wait_s, time_limit_min)

    @api.tool(intent=INTENT, listener=False)
    def rea_runs(limit: int = 50) -> dict:
        """List saved analyses, newest first."""
        return list_runs(limit)

    @api.tool(intent=INTENT, listener=False)
    def rea_get(run_id: str) -> dict:
        """One saved analysis with its digest and (when small) the full result."""
        return get_run(run_id)

    @api.tool(intent=INTENT, listener=False)
    def rea_delete(run_id: str) -> dict:
        """Delete one saved analysis and its files."""
        return delete_run(run_id)

    @api.tool(intent=INTENT, listener=False)
    def rea_apps() -> dict:
        """Running apps with a window, with their EXE and install folder, to point REA at."""
        return running_apps()

    @api.tool(intent=INTENT, listener=False)
    def rea_investigate(target: str = "", question: str = "", run_id: str = "") -> dict:
        """Open a chat where an agent reverse-engineers the target with all REA tools and answers the
        question with evidence. Works for websites too."""
        return investigate(target, question, run_id)

    @api.tool(intent=INTENT, listener=False)
    def rea_recreate(run_id: str = "", goal: str = "", mode: str = "solo", target: str = "") -> dict:
        """Recreate an analysed app as original code: makes Documents/REA Recreations/<name>/ with a brief
        (REA's findings), then opens a chat in the 'REA Recreations' chat group where an agent builds it.
        mode='team' has that agent plan and seat a multi-agent team. Many recreations can run at once."""
        return recreate(run_id, goal, mode, target)

    @api.tool(intent=INTENT, listener=False)
    def rea_recreation_update(recreation_id: str, note: str = "", status: str = "", percent: float = -1) -> dict:
        """Agents building a recreation report here: note = one milestone shown live in the panel,
        percent = 0-100, status = building | done | blocked | stopped."""
        return recreation_update(recreation_id, note, status, None if percent is None or percent < 0 else percent)

    @api.tool(intent=INTENT, listener=False)
    def rea_recreations() -> dict:
        """Every recreation, newest first: status, folder, file count, last change."""
        return list_recreations()

    @api.tool(intent=INTENT, listener=False)
    def rea_recreation_get(recreation_id: str) -> dict:
        """One recreation with its milestone notes and the files written so far."""
        return get_recreation(recreation_id)

    @api.tool(intent=INTENT, listener=False)
    def rea_recreation_delete(recreation_id: str, delete_files: bool = False) -> dict:
        """Remove a recreation from the list; delete_files=true also deletes its folder."""
        return delete_recreation(recreation_id, delete_files)

    @api.tool(intent=INTENT, listener=False)
    def rea_recreation_open(recreation_id: str = "", what: str = "folder") -> dict:
        """Open a recreation's folder in Explorer (what='folder'), its chat (what='chat'), or the
        whole REA Recreations folder (what='root')."""
        return open_recreation(recreation_id, what)

    # ---- workflow node -----------------------------------------------------------

    @api.register_pipeline_node("rea.run")
    def node_analyze(ctx: dict) -> dict:
        cfg = ctx.get("config") or {}
        inputs = ctx.get("inputs") or {}
        target = str(inputs.get("target") or cfg.get("target") or "")
        out = analyze(target, 3600)  # a workflow waits for the answer
        run = out.get("run") or {}
        return {**out, "digest": run.get("digest") or {}, "summary": run.get("name") or out.get("error", "")}

    @api.register_pipeline_node("rea.recreate")
    def node_recreate(ctx: dict) -> dict:
        cfg = ctx.get("config") or {}
        inputs = ctx.get("inputs") or {}
        pick = lambda k: str(inputs.get(k) or cfg.get(k) or "")  # noqa: E731
        out = recreate(pick("run_id"), pick("goal"), pick("mode") or "solo", pick("target"))
        rec = out.get("recreation") or {}
        return {**out, "folder": rec.get("folder", ""), "conv_id": rec.get("conv_id", "")}

    # ---- panel -------------------------------------------------------------------

    api.register_panel_rpc("status", lambda: status())
    api.register_panel_rpc("setup", lambda update=False, ghidra=False: setup(bool(update), ghidra=bool(ghidra)))
    # The panel's Cancel and the header activity list's Cancel on this plugin's job row.
    api.register_panel_rpc("cancel_job", lambda job_id="": cancel_job(job_id))
    # The panel barely waits: it shows the run's live steps (step 3) and flips to results on rea_runs_changed.
    api.register_panel_rpc("analyze", lambda target="": analyze(target, 1))
    api.register_panel_rpc("probe", lambda operation="", path="": probe(operation, path, 1))
    api.register_panel_rpc("runs", lambda limit=50: list_runs(limit))
    api.register_panel_rpc("get", lambda run_id="": get_run(run_id))
    api.register_panel_rpc("delete", lambda run_id="": delete_run(run_id))
    api.register_panel_rpc("apps", lambda: running_apps())
    api.register_panel_rpc("investigate", lambda target="", question="", run_id="": investigate(target, question, run_id))
    api.register_panel_rpc("recreate", lambda run_id="", goal="", mode="solo", target="": recreate(run_id, goal, mode, target))
    api.register_panel_rpc("recreations", lambda: list_recreations())
    api.register_panel_rpc("recreation_get", lambda recreation_id="": get_recreation(recreation_id))
    api.register_panel_rpc("recreation_update", lambda recreation_id="", note="", status="": recreation_update(recreation_id, note, status))
    api.register_panel_rpc("recreation_delete", lambda recreation_id="", delete_files=False: delete_recreation(recreation_id, bool(delete_files)))
    api.register_panel_rpc("recreation_open", lambda recreation_id="", what="folder": open_recreation(recreation_id, what))

    # ---- out of the box ------------------------------------------------------------

    def _register_once() -> None:
        # ponytail: a marker file per runtime; a re-register only when the server config changes.
        try:
            if _marker().read_text("utf-8") == json.dumps(_mcp_config(), sort_keys=True):
                return
        except OSError:
            pass
        if _register_mcp().get("ok"):
            _write_marker()

    if api.is_app():  # once, in the app; never per agent process
        # Recreations outlive Ducky (their chats go on): show the ones still building in the top bar again.
        for rec in data.items("recreation.").values():
            if rec.get("status") == "building":
                _rec_row(rec)
        if runtime.ready():
            threading.Thread(target=_register_once, name="rea-mcp-register", daemon=True).start()
        elif sys.platform == "win32" and api.is_enabled():
            # Turned on and not installed yet: set REA up now, nothing to press.
            setup()
    api.log("Reverse Engineer ready" if runtime.ready() else "Reverse Engineer: setting up REA")
