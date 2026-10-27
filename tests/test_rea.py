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


if __name__ == "__main__":
    test_manifest_shape()
    test_backend_sources_parse()
    test_payload_files_present()
    print("rea self-check ok")
