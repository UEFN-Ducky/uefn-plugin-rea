---
name: rea
description: "Reverse Engineer (REA): point at any app folder, EXE, DLL, .asar, game pack or model file and find how it's built; agents also get REA's 229 rea__* tools for decompiling, tracing and websites."
---

# Reverse Engineer (REA)

Plugin tools (quick, one shot):
- `rea_status()`: is REA installed (own Node 24.22.1 + rea-agents), version, setup progress.
- Setup is automatic: turning the plugin on downloads REA in the background (a row with progress and Cancel in the header's activity list). `rea_setup(update?, wait?)` re-runs or updates it (asks first); `rea_cancel_job()` cancels it.
- `rea_analyze(target)`: point at a folder (finds Unity / Unreal / Electron / .NET / Godot / GameMaker), an EXE/DLL, .asar, .pck, model file… Saves a run with candidates and next probes.
- `rea_probe(operation, path)`: run one next probe from a run (`inspect_pe_imports`, `analyze_javascript_application`, `inspect_il2cpp_metadata`, `inspect_managed_artifact`…).
- `rea_runs()`, `rea_get(run_id)`, `rea_delete(run_id)`: saved analyses.
- `rea_apps()`: running apps with windows and their install folders.
- `rea_investigate(target, question, run_id?)`: opens a chat where an agent digs in with all REA tools.

Slow REA work (`analyze_javascript_application` on a real app takes minutes): use `rea_probe` /
`rea_analyze`, not the `rea__` tool. They run in the background (header row with Cancel) and return
`running=true` past `wait_s`; then `rea_get(run_id)`. Saved results live under AppData, which file
tools can't open: read them with `rea__inspect_analysis_view` and
`{source: {kind: "evidence-file", path: <result_path>}, view: {kind: "summary"}}`.

Native decompiling (pseudocode, xrefs on EXEs/DLLs) uses Ghidra. `rea_status().ghidra` says if it is
installed; if not, `rea_setup(ghidra=true)` adds Ghidra 12.1.4 + its own JDK 21 (~650 MB, SHA-checked,
cancellable; asks first). Then `rea_probe("decompile", exe)` returns the entry function's pseudocode
and `rea_probe("analyze", exe)` a native overview; REA's `rea__*` session tools use the same Ghidra.
Static JS/.NET/desktop/PE inspection needs nothing extra.

A run that hits its time limit (big Electron apps can take hours) ends `status="partial"` with a
summary of everything found so far: report it as partial, not as a failure.

Recreations (rebuild an analysed app as original code):
- `rea_recreate(run_id, goal, mode="solo"|"team")`: makes `Documents/REA Recreations/<name>/` with
  `REA-BRIEF.md` (REA's findings) and opens a builder chat in the "REA Recreations" chat group.
  `mode="team"` has that chat plan and seat a multi-agent team. Many recreations can run at once.
- `rea_recreation_update(recreation_id, note, percent?, status?)`: **builders call this at every
  milestone**; the panel's Recreations page shows each note live. End with `status="done"` or `"blocked"`.
- `rea_recreations()`, `rea_recreation_get(id)` (notes + files), `rea_recreation_open(id, what="folder"|"chat"|"root")`,
  `rea_recreation_delete(id, delete_files?)`.
Builders write only inside their recreation folder and never copy the original's binaries, assets or code.

Deep work (xrefs, sessions, websites, captures): the nested `rea__*` tools. Find them with
`ducky_get_tools("rea")` and call with `ducky_call_tool`.

Rules: only software the person owns or may examine. Report the evidence and the unknowns REA returns.
