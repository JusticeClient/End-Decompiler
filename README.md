# End Decompiler

A desktop tool for inspecting Minecraft mod jars and native Windows binaries for malware. Drop in a `.jar`, `.dll`, or `.exe` and it decompiles the code and runs a static heuristics scan for RATs, token grabbers, injectors, and other nasty stuff.

It's purely static. The thing you load never runs — it gets unzipped/parsed, decompiled by trusted tools, and pattern-matched. Built with Tauri (Rust + a small TypeScript frontend), so it starts instantly and stays small.

## Two modes

Pick one from the menu:

- **Minecraft Mod** — opens a `.jar`/`.zip`/`.class`, lays out the package tree, decompiles classes on click (Vineflower, with CFR as a fallback), and scans for malicious patterns.
- **DLL / Executable** — parses the PE (headers, sections with entropy, imports, exports), disassembles native code (x86/x64), pulls strings, and for .NET assemblies decompiles the IL back to C#.

Both produce a ranked list of findings and an overall verdict (Clean / Suspicious / Likely Malicious / Malicious), which you can export to Markdown or JSON.

## What it detects

The engine keys on specific indicators rather than generic capabilities, so legit code stays clean:

- Discord webhooks, token regexes, browser/Discord `leveldb` and `Local State` theft, DPAPI, Minecraft launcher creds
- Process execution, encoded PowerShell, shell/LOLBins, defender tampering, persistence
- Reflection + decode/decrypt combos (packed payloads), Base64 that decodes to a webhook / IP / exe / class
- Surveillance (Robot screen capture, clipboard, keyloggers), self-propagation (fractureiser-style jar infection), cryptominers, anti-analysis/VM checks
- For PE files: dangerous imports (CreateRemoteThread, VirtualAllocEx, WinHttp…), W+X / high-entropy sections, resources that are secretly executables, and Authenticode signature awareness

## Building

Needs Node 18+ and Rust.

```
npm install
npm run tauri dev      # run it
npm run tauri build    # build the app
```

The Vineflower/CFR jars and the ILSpy decompiler are fetched into `src-tauri/resources/` on first run (`scripts/fetch-decompilers.mjs`).

### Installer

There's a custom Inno Setup installer in `installer/`:

```
npm run build
cd src-tauri && cargo build --release
cd ../installer && "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" setup.iss
```

It packages the exe + decompilers, handles WebView2, and ships a dark themed wizard.

## Runtime requirements

- **Java 17+** for decompiling mods (Vineflower/CFR/javap run on it).
- **.NET 6+ runtime** only for decompiling .NET assemblies to C#.

Neither is bundled; the app detects them and tells you if one's missing. Everything else (PE analysis, disassembly, strings, the verdict) works without them.

## Layout

```
src/              frontend (TS, CodeMirror, hand-written CSS)
src-tauri/src/    Rust backend
  archive.rs        jar extraction, constant-pool parsing
  decompile.rs      Vineflower / CFR / javap
  analysis.rs       the heuristics engine
  pe.rs             native PE analysis + disassembly + .NET decompile
  commands.rs       Tauri commands + session state
installer/        Inno Setup script + assets
```

## A note on the verdict

A "Clean" result means nothing matched, not that it's safe. This is a triage aid, not a sandbox. Check anything important against a trusted source before trusting it.
