# Reverse Engineer (`rea`)

A UEFN Ducky desktop plugin: point at any app, folder, EXE, DLL, archive or game
file and see how it's built in one click. Powered by
[REA (Reverse Engineer Anything)](https://github.com/morluto/rea), MIT. Agents get
all of REA's tools too.

## Out of the box

- **Installs itself.** Enable the plugin and it downloads a pinned Node runtime and
  REA on its own — nothing to press. The download shows in the top activity list and
  is **cancellable**; cancelling leaves nothing behind.
- **First-run walkthrough.** On first enable it points you at the header button and
  says: drop a folder, EXE, DLL or game file, or pick a running app.
- **Big targets run in the background.** Large apps (Electron, packed PE, .NET) run as
  background jobs you can watch or cancel; results too big to read inline come back as
  a short summary with next probes.

## Guided, step by step

The panel walks you through **Get ready → Pick something → Look inside → Results →
Recreate**: live %, a step log and elapsed time while REA works, a plain answer with
charts and confidence meters after, and one-click "look deeper" probes. Switches for
**Explain as I go**, **Technical details** and **History**. Everything keeps running
when you close the tab and shows in the top bar's activity list, with Cancel.

**Recreate it.** From a result, an agent (or a team of agents) rebuilds the app as
your own original code in `Documents/REA Recreations/<name>/`. The **Recreations**
tab lists them all; open one to see its milestones live, its files, its chat and
folder. Many can build at once.

## What it looks at

Native binaries (PE/ELF/Mach-O), .NET assemblies, Electron / packed JavaScript,
archives, and Godot / Unity / Unreal game data — whatever you point it at. Static JS /
.NET / desktop / PE inspection needs nothing extra.

**Native decompiler, one click.** Point at an EXE or DLL and press **Add native
decompiler**: the plugin installs Ghidra 12.1.4 with its own JDK 21 (~650 MB,
SHA-checked, cancellable, nothing system-wide) and REA's doctor checks it. Every EXE/DLL
then gets **Decompile** (entry function pseudocode) and a native Ghidra overview, and
agents' `rea__*` tools use the same Ghidra.

**Long runs.** JavaScript analysis may run up to 8 hours on a huge app. If it hits that
limit the run ends **partial** with a summary of everything found, not an error. Runs
survive a plugin update mid-run.

> [!NOTE] Only point it at software you own or are authorised to examine.
> The plugin inspects whatever path you give it and keeps no block list; honouring the
> licence and terms of what you analyse is on you.

## Layout

| Path | What |
|------|------|
| `plugin.json` | Manifest: panels, header button, walkthrough, automation node, agent tools. |
| `backend/__init__.py` | `register(api)`: auto-setup, background runs, result summarization, recreations, MCP wiring. |
| `backend/runtime.py` | Pinned Node download, REA install, run/cancel, progress parsing. |
| `ui/index.html` | 5-step wizard (setup, pick, live progress, results, recreate) and the Recreations gallery. |
| `skills/rea/SKILL.md` | Agent skill. |
| `scripts/` | `build_zip.py`, `commit_before_store.py`, `release.py`. |

## Build & publish

```sh
py scripts/build_zip.py                 # deploy/rea-<ver>.ducky-plugin.zip
py scripts/release.py --publish --changelog "1.0.0: ..."   # commit+push, then Store upload (needs DUCKYOS_API_KEY)
```

`py tests/test_rea.py` runs the static self-check; `ducky_plugin_test` runs the full
install/tool/panel test against this repo.
