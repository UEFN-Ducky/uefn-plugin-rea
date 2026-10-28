"""Self-check: the Reverse Engineer plugin reads the way UEFN Ducky loads it (no app host).

Static only — backend/__init__.py imports the desktop app host, which is absent in a
standalone clone, so we parse the sources instead of importing them.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_manifest_shape() -> None:
    m = json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))
    assert m["id"] == "rea"
    assert m["kind"] == "plugin"
    assert m["data_sharing"] is False
    assert m["backend"] == {"entry": "backend", "register": "register"}
    panels = m["contributes"]["ui.panels"]
    assert any(p["entry"] == "ui/index.html" for p in panels)
    wt = m["contributes"]["walkthrough"]
    assert wt["auto_start"] == "first_enable" and len(wt["steps"]) >= 2
    tools = m["contributes"]["agent.tools"]
    assert "rea_setup" in tools["destructive_tools"]
    assert "rea_status" in tools["plan_tools"]


def test_backend_sources_parse() -> None:
    for name in ("__init__.py", "runtime.py"):
        src = (ROOT / "backend" / name).read_text(encoding="utf-8")
        ast.parse(src)  # SyntaxError fails the test
    init = (ROOT / "backend" / "__init__.py").read_text(encoding="utf-8")
    assert "def register(" in init
    # Auto-setup must stay guarded to the app runtime, never fire from a bare import.
    assert "api.is_app()" in init


def test_payload_files_present() -> None:
    for rel in ("ui/index.html", "assets/icon.svg", "skills/rea/SKILL.md"):
        assert (ROOT / rel).is_file(), rel
    skill = (ROOT / "skills" / "rea" / "SKILL.md").read_text(encoding="utf-8")
    assert skill.startswith("---"), "SKILL.md needs frontmatter"


def test_timeout_keeps_partial_observation(tmp_path: Path | None = None) -> None:
    import sys
    import tempfile

    sys.path.insert(0, str(ROOT))
    from backend import _partial_observation

    tmp = tmp_path or Path(tempfile.mkdtemp())
    hit = tmp / "timeout.json"
    hit.write_text(json.dumps({"code": "provider_timeout", "details": {
        "partial_observation": {"evidence_id": "ev_1", "normalized_result": {}}}}), "utf-8")
    assert _partial_observation(hit) == {"evidence_id": "ev_1", "normalized_result": {}}
    bare = tmp / "bare.json"
    bare.write_text(json.dumps({"code": "provider_timeout", "details": {}}), "utf-8")
    assert _partial_observation(bare) is None
    assert _partial_observation(tmp / "missing.json") is None


def test_recreation_folders(tmp_path: Path | None = None) -> None:
    import sys
    import tempfile

    sys.path.insert(0, str(ROOT))
    from backend import _scan, _slug, _unique_folder

    tmp = tmp_path or Path(tempfile.mkdtemp())
    assert _slug('Grok: "AI"/app?') == "Grok AI app"
    assert _slug("???") == "Recreation"
    first = _unique_folder(tmp, "Grok")
    assert first.name == "Grok"
    first.mkdir()
    assert _unique_folder(tmp, "Grok").name == "Grok (2)"
    (first / "src").mkdir()
    (first / "src" / "main.js").write_text("x" * 10, "utf-8")
    (first / "node_modules" / "dep").mkdir(parents=True)
    (first / "node_modules" / "dep" / "big.js").write_text("y" * 999, "utf-8")
    scan = _scan(first)
    assert scan["file_count"] == 1 and scan["bytes"] == 10, scan  # node_modules never counted
    assert scan["files"][0]["path"] == "src/main.js"
    assert _scan(tmp / "missing") == {"file_count": 0, "bytes": 0, "last_change": 0, "files": []}


def test_manifest_lists_recreation_tools() -> None:
    m = json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))
    nodes = {n["id"] for n in m["contributes"]["automations"]["nodes"]}
    assert {"rea.run", "rea.recreate"} <= nodes
    init = (ROOT / "backend" / "__init__.py").read_text(encoding="utf-8")
    for name in ("rea_recreate", "rea_recreation_update", "rea_recreations", "rea_recreation_get",
                 "rea_recreation_delete", "rea_recreation_open"):
        assert f"def {name}(" in init, name
    destructive = m["contributes"]["agent.tools"]["destructive_tools"]
    assert "rea_recreate" in destructive
    # A bare rea_cancel_job() cancels the newest real run: sample-input tests must never call it.
    assert "rea_cancel_job" in destructive


def test_rea_processes_die_with_the_app() -> None:
    """Ducky closing mid-run (here: a parent that exits without cleanup) leaves no REA process behind."""
    import subprocess
    import sys
    import time

    if sys.platform != "win32":
        return
    grandchild = "import time; time.sleep(120)"
    child = f"import subprocess, sys, time; p = subprocess.Popen([sys.executable, '-c', {grandchild!r}]); print(p.pid, flush=True); time.sleep(120)"
    parent = (
        f"import subprocess, sys; sys.path.insert(0, {str(ROOT)!r}); from backend import runtime\n"
        f"p = subprocess.Popen([sys.executable, '-c', {child!r}], stdout=subprocess.PIPE, text=True)\n"
        "runtime._die_with_app(p)\n"
        "print(p.pid, p.stdout.readline().strip(), flush=True)\n"  # then exit without killing anything
    )
    out = subprocess.run([sys.executable, "-c", parent], capture_output=True, text=True, timeout=60)
    pids = out.stdout.split()
    assert len(pids) == 2, out
    alive = lambda pid: pid in subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],  # noqa: E731
                                              capture_output=True, text=True).stdout
    deadline = time.time() + 10
    while any(alive(p) for p in pids) and time.time() < deadline:
        time.sleep(0.3)
    assert not any(alive(p) for p in pids), f"left running: {[p for p in pids if alive(p)]}"


def test_orphan_cancel_matches_only_its_own_process() -> None:
    import sys

    sys.path.insert(0, str(ROOT))
    from backend.runtime import _matches

    needles = ("C:/rt/node_modules/rea-agents/bin/rea.js", "analyze-javascript-application", r"C:\Apps\Grok\resources\app.asar")
    mine = r'"C:\rt\node\node.exe" C:\rt\node_modules\rea-agents\bin\rea.js analyze-javascript-application "C:\Apps\Grok\resources\app.asar" --json'
    assert _matches(mine, needles)
    assert not _matches(mine.replace("analyze-javascript", "inspect-asar"), needles)  # another REA command
    assert not _matches(mine.replace("Grok", "Other"), needles)  # same command, other target
    assert not _matches(r"node C:\other\server.js app.asar analyze-javascript-application", needles)  # not REA
    assert not _matches("", needles)


if __name__ == "__main__":
    test_manifest_shape()
    test_backend_sources_parse()
    test_payload_files_present()
    test_timeout_keeps_partial_observation()
    test_recreation_folders()
    test_manifest_lists_recreation_tools()
    print("rea self-check ok")
