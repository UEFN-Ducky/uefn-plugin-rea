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

## What it looks at

Native binaries (PE/ELF/Mach-O), .NET assemblies, Electron / packed JavaScript,
archives, and Godot / Unity / Unreal game data — whatever you point it at. Native
pseudocode and xrefs need a local Ghidra, IDA or Hopper; static JS / .NET / desktop /
PE inspection needs nothing extra.

> [!NOTE] Only point it at software you own or are authorised to examine.
> The plugin inspects whatever path you give it and keeps no block list; honouring the
> licence and terms of what you analyse is on you.

## Layout

| Path | What |
|------|------|
| `plugin.json` | Manifest: panels, header button, walkthrough, automation node, agent tools. |
| `backend/__init__.py` | `register(api)`: auto-setup, background runs, result summarization, MCP wiring. |
| `backend/runtime.py` | Pinned Node download, REA install, run/cancel, progress parsing. |
| `ui/index.html` | Setup card, drop zone, pickers, live progress, Cancel. |
| `skills/rea/SKILL.md` | Agent skill. |
| `scripts/` | `build_zip.py`, `commit_before_store.py`, `release.py`. |

## Build & publish

```sh
py scripts/build_zip.py                 # deploy/rea-<ver>.ducky-plugin.zip
py scripts/release.py --publish --changelog "1.0.0: ..."   # commit+push, then Store upload (needs DUCKYOS_API_KEY)
```

`py backend/test_rea.py` runs the static self-check; `ducky_plugin_test` runs the full
install/tool/panel test against this repo.
