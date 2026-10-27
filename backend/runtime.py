"""REA's own runtime: a pinned, hash-checked Node and the rea-agents npm package.

Everything lives in one folder next to Ducky's sandbox runtimes; nothing is installed
system-wide. REA 6.x needs Node ^22.23.4 / ^24.22.1, newer than most PCs (and Ducky's
sandbox Node) have, so it brings its own.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable

NODE_VERSION = "24.22.1"
NODE_URL = f"https://nodejs.org/dist/v{NODE_VERSION}/node-v{NODE_VERSION}-win-x64.zip"
NODE_SHA256 = "d2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5"
REA_VERSION = "6.8.0"

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0

# progress(text, percent or None)
Progress = Callable[[str, "float | None"], None]


class Cancelled(Exception):
    """The person cancelled the setup."""


def root() -> Path:
    from backend.sandbox import paths

    return paths.tools_root().parent / "rea"


def node_dir() -> Path:
    return root() / f"node-{NODE_VERSION}"


def node_exe() -> Path:
    return node_dir() / "node.exe"


def app_dir() -> Path:
    return root() / "app"


def rea_js() -> Path:
    return app_dir() / "node_modules" / "rea-agents" / "scripts" / "rea.mjs"


def ready() -> bool:
    return node_exe().is_file() and rea_js().is_file()


def installed_version() -> str:
    try:
        pkg = json.loads((app_dir() / "node_modules" / "rea-agents" / "package.json").read_text("utf-8"))
        return str(pkg.get("version") or "")
    except (OSError, ValueError):
        return ""


def _env() -> dict:
    env = dict(os.environ)
    env["PATH"] = str(node_dir()) + os.pathsep + env.get("PATH", "")
    env["npm_config_cache"] = str(root() / "npm-cache")
    env["npm_config_update_notifier"] = "false"
    env["NO_COLOR"] = "1"
    return env


def _kill_tree(proc: subprocess.Popen) -> None:
    """REA and npm start worker processes: stop the whole tree, not just the parent."""
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True,
                       creationflags=_NO_WINDOW, stdin=subprocess.DEVNULL, timeout=30)
    else:
        proc.kill()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def _download(url: str, dest: Path, sha256: str, progress: Progress, cancel: threading.Event,
              lo: float, hi: float) -> None:
    """Stream ``url`` to ``dest``, checking its SHA-256; percent runs from ``lo`` to ``hi``."""
    digest = hashlib.sha256()
    part = dest.with_suffix(dest.suffix + ".part")
    try:
        with urllib.request.urlopen(url, timeout=60) as resp, open(part, "wb") as out:  # noqa: S310 — pinned https URL
            total = int(resp.headers.get("Content-Length") or 0)
            got = 0
            last = -1
            while True:
                if cancel.is_set():
                    raise Cancelled()
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                digest.update(chunk)
                got += len(chunk)
                pct = int(lo + (hi - lo) * got / total) if total else None
                if pct != last:
                    last = pct if pct is not None else last
                    mb = f"{got / 1048576:.0f}" + (f" of {total / 1048576:.0f}" if total else "")
                    progress(f"Downloading Node {NODE_VERSION} ({mb} MB)", pct)
        if digest.hexdigest() != sha256:
            raise RuntimeError("The Node download didn't match its published SHA-256; nothing was installed.")
        os.replace(part, dest)
    finally:
        part.unlink(missing_ok=True)


def ensure_node(progress: Progress, cancel: threading.Event) -> None:
    if node_exe().is_file():
        return
    base = root()
    base.mkdir(parents=True, exist_ok=True)
    zip_path = base / f"node-{NODE_VERSION}.zip"
    try:
        _download(NODE_URL, zip_path, NODE_SHA256, progress, cancel, 2, 55)
        progress("Unpacking Node…", 57)
        tmp = base / "node.part"
        shutil.rmtree(tmp, ignore_errors=True)
        with zipfile.ZipFile(zip_path) as zf:
            safe = tmp.resolve()
            for m in zf.infolist():
                if os.path.commonpath([str(safe), str((tmp / m.filename).resolve())]) != str(safe):
                    raise RuntimeError(f"unsafe path in the Node archive: {m.filename}")
            zf.extractall(tmp)
        if cancel.is_set():
            raise Cancelled()
        shutil.rmtree(node_dir(), ignore_errors=True)
        os.replace(tmp / f"node-v{NODE_VERSION}-win-x64", node_dir())
        shutil.rmtree(tmp, ignore_errors=True)
    finally:
        zip_path.unlink(missing_ok=True)
        shutil.rmtree(base / "node.part", ignore_errors=True)


def install_rea(progress: Progress, cancel: threading.Event, version: str = REA_VERSION) -> None:
    app = app_dir()
    app.mkdir(parents=True, exist_ok=True)
    pkg = app / "package.json"
    if not pkg.is_file():
        pkg.write_text('{"name": "ducky-rea-host", "private": true}\n', "utf-8")
    npm_cli = node_dir() / "node_modules" / "npm" / "bin" / "npm-cli.js"
    progress(f"Installing REA {version} (a minute or two)…", 62)
    proc = subprocess.Popen(
        [str(node_exe()), str(npm_cli), "install", "--no-audit", "--no-fund", "--save-exact", f"rea-agents@{version}"],
        cwd=str(app), env=_env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", creationflags=_NO_WINDOW, stdin=subprocess.DEVNULL,
    )
    tail: list[str] = []
    reader = threading.Thread(target=lambda: tail.extend(proc.stdout or []), daemon=True)
    reader.start()
    pct = 62.0
    while proc.poll() is None:
        if cancel.wait(1.0):
            _kill_tree(proc)
            raise Cancelled()
        pct = min(95.0, pct + 0.6)  # ponytail: npm prints no progress; a slow creep so it looks alive
        progress(f"Installing REA {version} (a minute or two)…", int(pct))
    reader.join(timeout=5)
    if proc.returncode != 0 or not rea_js().is_file():
        raise RuntimeError("".join(tail).strip()[-1200:] or "npm install failed")


def setup(progress: Progress, cancel: threading.Event, update: bool = False) -> None:
    if sys.platform != "win32":
        raise RuntimeError("Reverse Engineer sets up its runtime on Windows only.")
    ensure_node(progress, cancel)
    if update or not rea_js().is_file():
        install_rea(progress, cancel, "latest" if update else REA_VERSION)


def mcp_command() -> tuple[str, list[str]]:
    return str(node_exe()), [str(rea_js()), "mcp"]


_STEP = re.compile(r"\((\d+)/(\d+)\)")


def _progress_lines(err_path: Path, offset: int, on_progress: Progress) -> int:
    """Read REA's ``{"rea_progress": {...}}`` stderr lines past ``offset``; returns the new offset."""
    try:
        with open(err_path, "rb") as f:
            f.seek(offset)
            chunk = f.read()
    except OSError:
        return offset
    end = chunk.rfind(b"\n") + 1
    for line in chunk[:end].splitlines():
        try:
            msg = (json.loads(line).get("rea_progress") or {}).get("message") or ""
        except (ValueError, AttributeError):
            continue
        if msg:
            m = _STEP.search(msg)
            on_progress(msg[:160], int(100 * int(m[1]) / max(1, int(m[2]))) if m else None)
    return offset + end


def run(args: list[str], out_path: Path, cancel: threading.Event | None = None,
        timeout: float = 3600, on_progress: Progress | None = None) -> tuple[int, str]:
    """One REA CLI call, stdout streamed to ``out_path`` (Evidence can be hundreds of MB).

    Returns (exit code, the last of stderr). Raises Cancelled when ``cancel`` is set.
    ``on_progress(text, percent)`` hears REA's own progress lines."""
    if not ready():
        raise RuntimeError("REA is still setting up: watch the top bar's activity list, or open Reverse Engineer.")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    err_path = out_path.with_suffix(".stderr.txt")
    with open(out_path, "wb") as out, open(err_path, "wb") as err:
        proc = subprocess.Popen(
            [str(node_exe()), str(rea_js()), *args], cwd=str(root()), env=_env(), stdout=out, stderr=err,
            creationflags=_NO_WINDOW, stdin=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + timeout
        seen = 0
        while True:
            try:
                proc.wait(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                pass
            if on_progress is not None:
                seen = _progress_lines(err_path, seen, on_progress)
            stop = cancel is not None and cancel.is_set()
            if stop or time.monotonic() > deadline:
                _kill_tree(proc)
                if stop:
                    raise Cancelled()
                raise subprocess.TimeoutExpired(args, timeout)
    try:
        tail = err_path.read_bytes()[-2000:].decode("utf-8", "replace")
    except OSError:
        tail = ""
    return proc.returncode, tail
