import "./styles.css";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { load as loadStore, type Store } from "@tauri-apps/plugin-store";
import { api, onDecompileProgress } from "./api";
import { CodeViewer } from "./ui/editor";
import { icon } from "./ui/icons";
import { applyTheme, loadTheme, saveTheme, PRESETS, DEFAULT_THEME, type Theme } from "./ui/theme";
import type {
  AnalysisReport,
  ArchiveInfo,
  DecompileResult,
  DllReport,
  Finding,
  JavaInfo,
  Metadata,
  PeImport,
  StringEntry,
} from "./types";

interface OpenArchive {
  info: ArchiveInfo;
  expanded: Set<string>;
  decompile: Map<string, { source?: DecompileResult; bytecode?: DecompileResult }>;
  strings?: StringEntry[];
  metadata?: Metadata;
  analysis?: AnalysisReport;
  flagged: Set<string>;
  decompiledAll: boolean;
}

interface Tab {
  archiveId: number;
  internalName: string;
  mode: "source" | "bytecode";
}

interface DllState {
  path: string;
  report?: DllReport;
  strings?: StringEntry[];
  view: "info" | "imports" | "strings";
  stringFilter: "all" | "url" | "ip" | "path" | "base64";
  asmLoaded: boolean;
}

const S = {
  mode: "menu" as "menu" | "mod" | "dll",
  archives: new Map<number, OpenArchive>(),
  order: [] as number[],
  active: null as number | null,
  tabs: [] as Tab[],
  activeTab: -1,
  leftView: "structure" as "structure" | "strings" | "metadata",
  stringFilter: "all" as "all" | "url" | "ip" | "path" | "base64",
  java: { found: false, usable: false } as JavaInfo,
  scan: "idle",
  dll: null as DllState | null,
};

let editor: CodeViewer;
let dllEditor: CodeViewer;
let store: Store | null = null;
let theme: Theme = loadTheme();

const $ = <T extends HTMLElement = HTMLElement>(sel: string) =>
  document.querySelector(sel) as T;

function el(html: string): HTMLElement {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild as HTMLElement;
}

function esc(s: string): string {
  return s.replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!
  );
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

const activeArchive = () => (S.active != null ? S.archives.get(S.active) : undefined);

function toast(message: string, kind: "info" | "ok" | "error" = "info", ms = 4200) {
  const host = document.getElementById("toasts");
  if (!host) return;
  const ic = kind === "error" ? "alert" : kind === "ok" ? "shield" : "info";
  const t = el(`<div class="toast ${kind}">${icon(ic)}<span>${esc(message)}</span></div>`);
  host.appendChild(t);
  setTimeout(() => {
    t.classList.add("fade");
    setTimeout(() => t.remove(), 400);
  }, ms);
}

function shell(): string {
  return `
  <div id="bg-layer"></div>
  <div class="titlebar">
    <div class="brand"><span class="mark"></span><b>End&nbsp;Decompiler</b><span class="dim" id="brand-sub">forensic analysis</span></div>
    <div class="drag" data-tauri-drag-region></div>
    <div class="wc settings" id="btn-settings" title="Settings">${icon("settings")}</div>
    <div class="win-controls">
      <div class="wc" id="win-min">${icon("min")}</div>
      <div class="wc" id="win-max">${icon("max")}</div>
      <div class="wc close" id="win-close">${icon("x")}</div>
    </div>
  </div>

  <div class="modal-wrap" id="settings-modal">
    <div class="modal">
      <div class="modal-head">${icon("settings")} <b>Settings</b> <span class="modal-x" id="settings-close">${icon("x")}</span></div>
      <div class="modal-body">
        <div class="set-section">
          <div class="set-label">Theme preset</div>
          <div class="preset-row" id="preset-row"></div>
        </div>
        <div class="set-section">
          <div class="set-row">
            <div><div class="set-label">Accent color</div><div class="set-hint">active states, focus, the verdict</div></div>
            <input type="color" id="set-accent" class="color-in" />
          </div>
          <div class="set-row">
            <div><div class="set-label">Text color</div><div class="set-hint">primary foreground</div></div>
            <input type="color" id="set-text" class="color-in" />
          </div>
        </div>
        <div class="set-section">
          <div class="set-label">Background</div>
          <div class="set-hint">use an image as your backdrop — panels go translucent so it shows through</div>
          <div class="bg-controls">
            <button id="set-bg-pick">${icon("image")} Choose image…</button>
            <button id="set-bg-clear">Clear</button>
          </div>
          <div class="set-row" id="bg-dim-row">
            <div><div class="set-label">Backdrop dim</div><div class="set-hint">darken the image for readability</div></div>
            <input type="range" id="set-bg-dim" min="40" max="96" class="range-in" />
          </div>
        </div>
        <div class="set-foot">
          <button id="set-reset">${icon("reset")} Reset to default</button>
          <button class="primary" id="set-done">Done</button>
        </div>
      </div>
    </div>
  </div>

  <div class="toolbar" id="toolbar">
    <button id="btn-menu" title="Back to menu">${icon("list")} Menu</button>
    <div class="sep"></div>
    <div class="tb-group" id="tb-mod">
      <button class="primary" id="btn-open">${icon("open")} Open</button>
      <button id="btn-decompile-all" disabled>${icon("play")} Decompile all</button>
      <button id="btn-analyze" disabled>${icon("shield")} Analyze</button>
      <button id="btn-export" disabled>${icon("download")} Export</button>
    </div>
    <div class="tb-group" id="tb-dll" style="display:none">
      <button class="primary" id="btn-open-dll">${icon("open")} Open DLL</button>
      <button id="btn-disasm" disabled>${icon("binary")} Disassemble</button>
      <button id="btn-export-dll" disabled>${icon("download")} Export report</button>
    </div>
    <div class="identity" id="identity"></div>
    <div class="spacer"></div>
    <div class="search" id="search-box">${icon("search")}<input id="find" placeholder="Find in jar  (Ctrl+Shift+F)" /></div>
  </div>

  <div class="banner" id="banner">
    ${icon("alert")}
    <span id="banner-text"></span>
    <span class="close" id="banner-close">${icon("x")}</span>
  </div>

  <div id="menu-screen">
    <div class="menu-inner">
      <div class="menu-logo"><span class="mark"></span> <b>End Decompiler</b></div>
      <p class="menu-sub">Forensic static analysis. Pick what you're inspecting — nothing is ever executed.</p>
      <div class="menu-cards">
        <div class="menu-card has-img" id="card-mod" style="--card-img:url('/minecraft.jpg')">
          ${icon("cube", "card-ic")}
          <div class="card-title">Minecraft Mod</div>
          <div class="card-desc">Decompile a jar and scan for RATs, token grabbers, and malicious patterns.</div>
          <div class="card-ext">jar · zip · class</div>
        </div>
        <div class="menu-card" id="card-dll">
          ${icon("binary", "card-ic")}
          <div class="card-title">DLL / Executable</div>
          <div class="card-desc">PE analysis: imports, sections, entropy, strings, x86/x64 disassembly — and .NET assemblies decompiled to C#.</div>
          <div class="card-ext">dll · exe · .NET</div>
        </div>
      </div>
      <div class="menu-foot" id="menu-java"></div>
    </div>
  </div>

  <div class="main" id="dll-main" style="display:none">
    <div class="pane pane-left">
      <div class="panel-head" id="dll-tabs">
        <div class="ptab active" data-dview="info">${icon("info")} PE Info</div>
        <div class="ptab" data-dview="imports">Imports <span class="count" id="dc-imports"></span></div>
        <div class="ptab" data-dview="strings">Strings <span class="count" id="dc-strings"></span></div>
      </div>
      <div class="panel-body" id="dll-info"></div>
      <div class="panel-body hidden" id="dll-imports"></div>
      <div class="panel-body hidden" id="dll-strings"></div>
    </div>
    <div class="splitter" id="dsplit-left"></div>
    <div class="pane pane-center">
      <div class="editor-toolbar" id="dll-asm-bar" style="display:none">
        <span class="engine" id="dll-asm-engine">x86/x64 disassembly</span>
        <span class="note" id="dll-asm-note"></span>
      </div>
      <div class="editor-host" id="dll-editor-host" style="display:none"></div>
      <div class="empty" id="dll-empty">
        <div class="inner">
          <div class="frame"></div>
          <div class="big">Open a .dll or .exe</div>
          <div class="small">dll · exe &nbsp;|&nbsp; static PE analysis · never executed</div>
        </div>
      </div>
    </div>
    <div class="splitter" id="dsplit-right"></div>
    <div class="pane pane-right">
      <div class="panel-head"><div class="ptab active">${icon("shield")} Threat analysis</div></div>
      <div class="verdict" id="dll-verdict" style="display:none"></div>
      <div class="findings" id="dll-findings"><div class="placeholder">Open a DLL/EXE to analyze.</div></div>
    </div>
  </div>

  <div class="main" id="main">
    <div class="pane pane-left">
      <div class="panel-head" id="left-tabs">
        <div class="ptab active" data-view="structure">${icon("list")} Structure <span class="count" id="c-classes"></span></div>
        <div class="ptab" data-view="strings">Strings <span class="count" id="c-strings"></span></div>
        <div class="ptab" data-view="metadata">Metadata</div>
      </div>
      <div class="panel-body" id="left-structure"><div class="tree" id="tree"></div></div>
      <div class="panel-body hidden" id="left-strings"></div>
      <div class="panel-body hidden" id="left-metadata"></div>
    </div>

    <div class="splitter" id="split-left"></div>

    <div class="pane pane-center">
      <div class="tabbar" id="tabbar"></div>
      <div class="editor-toolbar" id="editor-toolbar" style="display:none">
        <div class="seg">
          <button data-mode="source" class="active" id="m-source">${icon("code")} Source</button>
          <button data-mode="bytecode" id="m-bytecode">${icon("binary")} Bytecode</button>
        </div>
        <span class="note" id="dec-note"></span>
        <span class="engine" id="dec-engine"></span>
      </div>
      <div class="editor-host" id="editor-host" style="display:none"></div>
      <div class="empty" id="empty">
        <div class="inner">
          <div class="frame"></div>
          <div class="big">Drop a .jar to begin</div>
          <div class="small">jar · zip · class &nbsp;|&nbsp; or press Ctrl+O</div>
        </div>
      </div>
      <div class="gsearch" id="gsearch">
        <div class="box">
          <div class="ipt">${icon("search")}<input id="gsearch-input" placeholder="Search across decompiled source" /><span class="hint">Enter</span></div>
          <div class="results" id="gsearch-results"></div>
        </div>
      </div>
    </div>

    <div class="splitter" id="split-right"></div>

    <div class="pane pane-right">
      <div class="panel-head"><div class="ptab active">${icon("shield")} Threat analysis</div></div>
      <div class="verdict" id="verdict" style="display:none"></div>
      <div class="findings" id="findings">
        <div class="placeholder">Open a jar and run <b>Analyze</b><br/>to scan for malicious patterns.</div>
      </div>
    </div>
  </div>

  <div id="toasts"></div>

  <div class="statusbar">
    <div class="seg" id="st-java"><span class="dot warn"></span>Java —</div>
    <div class="seg" id="st-engine">Vineflower + CFR</div>
    <div class="seg" id="st-classes">No archive</div>
    <div class="seg right" id="st-scan">
      <span id="st-scan-text">Ready</span>
      <div class="progress" id="st-progress" style="display:none"><div class="bar" id="st-bar"></div></div>
    </div>
  </div>
  `;
}

async function init() {
  $("#app").innerHTML = shell();
  editor = new CodeViewer($("#editor-host"));
  dllEditor = new CodeViewer($("#dll-editor-host"));

  applyTheme(theme);
  setMode("menu");
  wireToolbar();
  wireLeftTabs();
  wireMenu();
  wireSettings();
  wireSplitters();
  wireShortcuts();
  wireGlobalSearch();
  try {
    wireWindow();
  } catch (e) {
    console.warn("window controls unavailable", e);
  }
  wireDragDrop().catch((e) => console.warn("drag-drop unavailable", e));

  try {
    store = await loadStore("recent.json", { autoSave: true, defaults: {} });
  } catch {
    store = null;
  }

  await refreshJava();
  onDecompileProgress((p) => {
    if (p.id !== S.active) return;
    const pct = p.total ? Math.round((p.done / p.total) * 100) : 0;
    setScan(`Decompiling ${p.done}/${p.total}`, pct);
    if (p.current === "done") setScan("Decompiled", 100);
  });

  document.addEventListener("click", () => closeCtx());
}

function wireWindow() {
  const w = getCurrentWindow();
  $("#win-min").onclick = () => w.minimize();
  $("#win-max").onclick = () => w.toggleMaximize();
  $("#win-close").onclick = () => w.close();
}

function wireToolbar() {
  $("#btn-open").onclick = () => pickAndOpen();
  $("#btn-decompile-all").onclick = () => runDecompileAll();
  $("#btn-analyze").onclick = () => runAnalyze();
  $("#btn-export").onclick = () => exportMenu();
  const find = $<HTMLInputElement>("#find");
  find.onkeydown = (e) => {
    if (e.key === "Enter") openGlobalSearch(find.value);
  };
  $("#banner-close").onclick = () => $("#banner").classList.remove("show");
}

function wireLeftTabs() {
  $("#left-tabs").addEventListener("click", (e) => {
    const tab = (e.target as HTMLElement).closest(".ptab") as HTMLElement;
    if (!tab) return;
    setLeftView(tab.dataset.view as typeof S.leftView);
  });
}

function setLeftView(v: typeof S.leftView) {
  S.leftView = v;
  for (const t of document.querySelectorAll<HTMLElement>(".ptab[data-view]"))
    t.classList.toggle("active", t.dataset.view === v);
  $("#left-structure").classList.toggle("hidden", v !== "structure");
  $("#left-strings").classList.toggle("hidden", v !== "strings");
  $("#left-metadata").classList.toggle("hidden", v !== "metadata");
  if (v === "strings") renderStrings();
  if (v === "metadata") renderMetadata();
}

async function refreshJava() {
  try {
    S.java = await api.detectJava();
  } catch {
    S.java = { found: false, usable: false } as JavaInfo;
  }
  const seg = $("#st-java");
  const dot = S.java.usable ? "ok" : S.java.found ? "warn" : "bad";
  seg.innerHTML = `<span class="dot ${dot}"></span>Java ${
    S.java.found ? S.java.version || S.java.major : "not found"
  }`;
  const mj = document.getElementById("menu-java");
  if (mj) {
    mj.innerHTML = S.java.usable
      ? `Java ${esc(S.java.version || String(S.java.major))} ready · DLL analysis needs no Java`
      : `Mod decompilation needs Java 17+ (DLL analysis works without it)`;
  }
  const banner = $("#banner");
  if (!S.java.usable) {
    $("#banner-text").innerHTML = `${esc(
      S.java.note
    )} &nbsp;Get one at <a id="java-dl">adoptium.net</a> &nbsp;·&nbsp; <a id="java-retry">Re-check</a>`;
    banner.classList.add("show");
    const dl = document.getElementById("java-dl");
    if (dl) dl.onclick = () => openExternal("https://adoptium.net/temurin/releases/?version=21");
    const rt = document.getElementById("java-retry");
    if (rt) rt.onclick = () => refreshJava();
  } else {
    banner.classList.remove("show");
  }
}

async function openExternal(url: string) {
  try {
    const a = document.createElement("a");
    a.href = url;
    a.target = "_blank";
    a.rel = "noreferrer";
    a.click();
  } catch {
  }
}

async function pickAndOpen() {
  const selected = await openDialog({
    multiple: false,
    filters: [{ name: "Java archive", extensions: ["jar", "zip", "class"] }],
  });
  if (!selected) return;
  const path = Array.isArray(selected) ? selected[0] : selected;
  await openPath(path as string);
}

async function closeAllArchives() {
  const ids = [...S.order];
  S.archives.clear();
  S.order = [];
  S.tabs = [];
  S.activeTab = -1;
  S.active = null;
  renderTabs();
  renderTree();
  renderThreat();
  $("#identity").classList.remove("show");
  $("#identity").innerHTML = "";
  for (const id of ids) {
    try {
      await api.closeArchive(id);
    } catch {
    }
  }
}

async function openPath(path: string) {
  setScan("Opening…");
  await closeAllArchives();
  try {
    const info = await api.openArchive(path);
    const arc: OpenArchive = {
      info,
      expanded: new Set<string>([rootKey(info.id)]),
      decompile: new Map(),
      flagged: new Set(),
      decompiledAll: false,
    };
    S.archives.set(info.id, arc);
    if (!S.order.includes(info.id)) S.order.push(info.id);
    S.active = info.id;
    await addRecent(path);
    renderTree();
    renderThreat();
    updateToolbar();
    updateStatus();
    setScan("Ready");
    void loadIdentity(arc);
  } catch (e) {
    setScan("Open failed");
    toast(`Failed to open archive: ${e}`, "error", 7000);
  }
}

async function loadIdentity(arc: OpenArchive) {
  try {
    arc.metadata = await api.getMetadata(arc.info.id);
    const m = arc.metadata;
    const name = m.modName || m.modId || arc.info.name;
    const author = m.authors.length ? m.authors.join(", ") : "unknown author";
    toast(`Viewing ${name} by ${author}`, "info");
    updateStatus();
  } catch (e) {
    toast(`Couldn't read mod metadata: ${e}`, "error", 7000);
  }
}

const rootKey = (id: number) => `@root:${id}`;

interface TNode {
  name: string;
  path: string;
  type: "pkg" | "class";
  internal?: string;
  size?: number;
  children: Map<string, TNode>;
}

function buildTree(info: ArchiveInfo): TNode {
  const root: TNode = { name: info.name, path: rootKey(info.id), type: "pkg", children: new Map() };
  for (const c of info.classes) {
    if (c.inner) continue;
    const parts = c.internalName.split("/");
    let node = root;
    for (let i = 0; i < parts.length; i++) {
      const isLeaf = i === parts.length - 1;
      const key = parts[i];
      if (!node.children.has(key)) {
        node.children.set(key, {
          name: key,
          path: `${node.path}/${key}`,
          type: isLeaf ? "class" : "pkg",
          internal: isLeaf ? c.internalName : undefined,
          size: isLeaf ? c.size : undefined,
          children: new Map(),
        });
      }
      node = node.children.get(key)!;
    }
  }
  collapseChains(root);
  return root;
}

function collapseChains(node: TNode) {
  for (const child of node.children.values()) {
    while (
      child.type === "pkg" &&
      child.children.size === 1 &&
      [...child.children.values()][0].type === "pkg"
    ) {
      const only = [...child.children.values()][0];
      child.name = `${child.name}.${only.name}`;
      child.path = only.path;
      child.children = only.children;
    }
    collapseChains(child);
  }
}

function renderTree() {
  const tree = $("#tree");
  tree.innerHTML = "";
  $("#c-classes").textContent = String(
    [...S.archives.values()].reduce((a, x) => a + x.info.classCount, 0) || ""
  );
  for (const id of S.order) {
    const arc = S.archives.get(id);
    if (!arc) continue;
    const root = buildTree(arc.info);
    renderNode(tree, root, 0, arc, true);
    if (arc.info.resources.length) {
      const sec = el(`<div class="section">Resources · ${arc.info.resources.length}</div>`);
      tree.appendChild(sec);
      for (const r of groupResources(arc.info)) {
        const row = el(
          `<div class="node" style="padding-left:${10}px"><span class="twist"></span>${icon(
            "file",
            "ico"
          )}<span class="label">${esc(r.path)}</span><span class="badge">${esc(r.kind)}</span></div>`
        );
        row.onclick = () => openResource(arc, r.path);
        tree.appendChild(row);
      }
    }
  }
}

function groupResources(info: ArchiveInfo) {
  const order = ["descriptor", "manifest", "config", "asset", "other"];
  return [...info.resources].sort(
    (a, b) => order.indexOf(a.kind) - order.indexOf(b.kind) || a.path.localeCompare(b.path)
  );
}

function renderNode(
  container: HTMLElement,
  node: TNode,
  depth: number,
  arc: OpenArchive,
  isRoot = false
) {
  const expanded = arc.expanded.has(node.path);
  const pad = 6 + depth * 12;

  if (node.type === "class") {
    const sel =
      S.activeTab >= 0 &&
      S.tabs[S.activeTab]?.archiveId === arc.info.id &&
      S.tabs[S.activeTab]?.internalName === node.internal;
    const flagged = arc.flagged.has(node.internal!);
    const row = el(
      `<div class="node ${sel ? "selected" : ""} ${flagged ? "flag" : ""}" style="padding-left:${pad}px">
        <span class="twist"></span>${icon("class", "ico")}
        <span class="label">${esc(node.name)}</span></div>`
    );
    row.onclick = () => openClass(arc.info.id, node.internal!);
    row.oncontextmenu = (e) => classCtx(e, arc.info.id, node.internal!);
    container.appendChild(row);
    return;
  }

  const cls = isRoot ? "pkg root" : "pkg";
  const twist = node.children.size ? (expanded ? "▾" : "▸") : "";
  const badge = isRoot ? `<span class="badge">${arc.info.classCount} cls · ${fmtSize(arc.info.totalSize)}</span>` : "";
  const row = el(
    `<div class="node ${cls}" style="padding-left:${pad}px">
      <span class="twist">${twist}</span>${icon(isRoot ? "cube" : expanded ? "folder-open" : "folder", "ico")}
      <span class="label">${esc(node.name)}</span>${badge}</div>`
  );
  row.onclick = () => {
    if (arc.expanded.has(node.path)) arc.expanded.delete(node.path);
    else arc.expanded.add(node.path);
    S.active = arc.info.id;
    renderTree();
    updateToolbar();
    updateStatus();
  };
  if (isRoot) row.oncontextmenu = (e) => archiveCtx(e, arc.info.id);
  container.appendChild(row);

  if (expanded) {
    const kids = [...node.children.values()].sort((a, b) => {
      if (a.type !== b.type) return a.type === "pkg" ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
    for (const k of kids) renderNode(container, k, depth + 1, arc);
  }
}

function tabKey(t: Tab) {
  return `${t.archiveId}:${t.internalName}`;
}

async function openClass(archiveId: number, internalName: string) {
  S.active = archiveId;
  const existing = S.tabs.findIndex(
    (t) => t.archiveId === archiveId && t.internalName === internalName
  );
  if (existing >= 0) {
    S.activeTab = existing;
  } else {
    S.tabs.push({ archiveId, internalName, mode: "source" });
    S.activeTab = S.tabs.length - 1;
  }
  renderTabs();
  renderTree();
  updateToolbar();
  updateStatus();
  await loadCurrent();
}

function renderTabs() {
  const bar = $("#tabbar");
  bar.innerHTML = "";
  S.tabs.forEach((t, i) => {
    const simple = t.internalName.split("/").pop();
    const tab = el(
      `<div class="tab ${i === S.activeTab ? "active" : ""}">
        ${icon(t.mode === "bytecode" ? "binary" : "class", "icon")}
        <span class="name">${esc(simple || t.internalName)}</span>
        <span class="x">${icon("x")}</span></div>`
    );
    tab.onclick = (e) => {
      if ((e.target as HTMLElement).closest(".x")) {
        closeTab(i);
      } else {
        S.activeTab = i;
        S.active = t.archiveId;
        renderTabs();
        renderTree();
        loadCurrent();
        updateStatus();
      }
    };
    bar.appendChild(tab);
  });
  const has = S.tabs.length > 0;
  $("#empty").style.display = has ? "none" : "grid";
  $("#editor-host").style.display = has ? "block" : "none";
  $("#editor-toolbar").style.display = has ? "flex" : "none";
}

function closeTab(i: number) {
  S.tabs.splice(i, 1);
  if (S.activeTab >= S.tabs.length) S.activeTab = S.tabs.length - 1;
  renderTabs();
  renderTree();
  if (S.activeTab >= 0) loadCurrent();
  updateStatus();
}

async function loadCurrent() {
  if (S.activeTab < 0) return;
  const tab = S.tabs[S.activeTab];
  const arc = S.archives.get(tab.archiveId);
  if (!arc) return;
  $("#m-source").classList.toggle("active", tab.mode === "source");
  $("#m-bytecode").classList.toggle("active", tab.mode === "bytecode");
  $("#dec-note").textContent = "";
  $("#dec-engine").textContent = "decompiling…";

  const result = await getDecompiled(arc, tab.internalName, tab.mode);
  if (S.activeTab < 0 || tabKey(S.tabs[S.activeTab]) !== tabKey(tab)) return;
  editor.setDoc(result.code, result.language);
  $("#dec-note").textContent = result.note || "";
  $("#dec-engine").textContent = `${result.decompiler}${result.fellBack ? " (fallback)" : ""}`;
}

async function getDecompiled(
  arc: OpenArchive,
  internalName: string,
  mode: "source" | "bytecode"
): Promise<DecompileResult> {
  const key = mode === "source" ? internalName.split("$")[0] : internalName;
  let slot = arc.decompile.get(key);
  if (!slot) {
    slot = {};
    arc.decompile.set(key, slot);
  }
  if (mode === "source" && slot.source) return slot.source;
  if (mode === "bytecode" && slot.bytecode) return slot.bytecode;

  if (!S.java.usable) {
    return {
      internalName,
      mode,
      language: "java",
      code: `// Java 17+ is required to decompile.\n// ${S.java.note}`,
      decompiler: "none",
      fellBack: false,
      note: "Java runtime missing",
    };
  }
  try {
    const res = await api.decompileClass(arc.info.id, internalName, mode);
    if (mode === "source") slot.source = res;
    else slot.bytecode = res;
    return res;
  } catch (e) {
    return {
      internalName,
      mode,
      language: "java",
      code: `// Decompilation failed.\n// ${e}`,
      decompiler: "none",
      fellBack: true,
      note: String(e),
    };
  }
}

function wireModeButtons() {
  $("#editor-toolbar").addEventListener("click", (e) => {
    const b = (e.target as HTMLElement).closest("button[data-mode]") as HTMLElement;
    if (!b || S.activeTab < 0) return;
    S.tabs[S.activeTab].mode = b.dataset.mode as "source" | "bytecode";
    renderTabs();
    loadCurrent();
  });
}

async function runDecompileAll() {
  const arc = activeArchive();
  if (!arc) return;
  setScan("Decompiling all…", 0, true);
  $("#btn-decompile-all").setAttribute("disabled", "");
  try {
    const n = await api.decompileAll(arc.info.id);
    arc.decompiledAll = true;
    arc.decompile.clear();
    setScan("Decompiled all", 100);
    toast(`Decompiled ${n} classes`, "ok");
    if (S.activeTab >= 0) loadCurrent();
  } catch (e) {
    setScan("Decompile failed");
    toast(`Decompile all failed: ${e}`, "error", 7000);
  } finally {
    $("#btn-decompile-all").removeAttribute("disabled");
    setTimeout(() => hideProgress(), 1200);
  }
}

async function runAnalyze() {
  const arc = activeArchive();
  if (!arc) return;
  setScan("Analyzing…", undefined, true);
  try {
    const report = await api.analyzeArchive(arc.info.id);
    arc.analysis = report;
    arc.flagged = new Set(
      report.findings
        .filter((f) => f.severity === "critical" || f.severity === "high")
        .map((f) => f.class)
    );
    renderThreat();
    renderTree();
    updateToolbar();
    setScan(`Verdict: ${report.verdict.label}`, 100);
    const kind = report.verdict.level === "clean" ? "ok" : "info";
    toast(
      `Scan complete — ${report.verdict.label}: ${report.findings.length} finding${
        report.findings.length === 1 ? "" : "s"
      }`,
      kind,
      5200
    );
  } catch (e) {
    setScan("Analysis failed");
    toast(`Analysis failed: ${e}`, "error", 7000);
  } finally {
    setTimeout(() => hideProgress(), 1200);
  }
}

function renderVerdictInto(verdictEl: HTMLElement, r: AnalysisReport, unitLabel: string) {
  verdictEl.style.display = "block";
  verdictEl.className = `verdict ${r.verdict.level}`;
  const sev = Object.fromEntries(r.severityCounts);
  verdictEl.innerHTML = `
    <div class="level"><span class="dot"></span>${esc(r.verdict.label)}</div>
    <div class="reason">${esc(r.verdict.reasoning)}</div>
    <div class="meters">
      <span class="meter crit"><b>${sev.critical || 0}</b> critical</span>
      <span class="meter high"><b>${sev.high || 0}</b> high</span>
      <span class="meter medium"><b>${sev.medium || 0}</b> medium</span>
      <span class="meter"><b>${sev.low || 0}</b> low</span>
      <span class="meter"><b>${r.classesScanned}</b> ${unitLabel}</span>
    </div>`;
}

function renderFindingsInto(
  list: HTMLElement,
  r: AnalysisReport,
  onClick: (f: Finding) => void
) {
  list.innerHTML = "";
  if (!r.findings.length) {
    list.innerHTML = `<div class="placeholder">No suspicious patterns detected.<br/>Always verify against a trusted source.</div>`;
    return;
  }
  for (const f of r.findings) {
    const row = el(
      `<div class="finding ${f.severity}">
        <div class="top">
          <span class="sev">${f.severity}</span>
          <span class="cat">${esc(f.category)}</span>
          <span class="loc">${esc(shortClass(f.class))}${f.line ? ":" + f.line : ""}</span>
        </div>
        <div class="why">${esc(f.why)}</div>
        <div class="snip">${esc(f.snippet)}</div>
      </div>`
    );
    row.onclick = () => onClick(f);
    list.appendChild(row);
  }
}

function renderThreat() {
  const arc = activeArchive();
  const verdictEl = $("#verdict");
  const list = $("#findings");
  if (!arc || !arc.analysis) {
    verdictEl.style.display = "none";
    list.innerHTML = `<div class="placeholder">${
      arc ? "Run <b>Analyze</b> to scan this jar<br/>for malicious patterns." : "Open a jar to begin."
    }</div>`;
    return;
  }
  renderVerdictInto(verdictEl, arc.analysis, "classes");
  renderFindingsInto(list, arc.analysis, (f) => jumpToFinding(arc, f));
}

const shortClass = (c: string) => c.split("/").pop() || c;

async function jumpToFinding(arc: OpenArchive, f: Finding) {
  if (!f.class) return;
  S.active = arc.info.id;
  await openClass(arc.info.id, f.class);
  if (S.tabs[S.activeTab]?.mode !== "source") {
    S.tabs[S.activeTab].mode = "source";
    renderTabs();
    await loadCurrent();
  }
  if (f.line) setTimeout(() => editor.jumpToLine(f.line), 60);
}

async function renderStrings() {
  const arc = activeArchive();
  const host = $("#left-strings");
  if (!arc) {
    host.innerHTML = `<div class="placeholder" style="padding:20px;color:var(--text-faint)">No archive open.</div>`;
    return;
  }
  if (!arc.strings) {
    host.innerHTML = `<div class="strings-filters"></div><div style="padding:14px;color:var(--text-faint);font-size:11.5px">Extracting strings…</div>`;
    try {
      arc.strings = await api.getStrings(arc.info.id);
    } catch (e) {
      host.innerHTML = `<div style="padding:14px;color:var(--sev-high);font-size:11.5px">Couldn't extract strings:<br/>${esc(
        String(e)
      )}</div>`;
      toast(`Strings failed: ${e}`, "error", 7000);
      return;
    }
  }
  const all = arc.strings;
  $("#c-strings").textContent = String(all.length || "");
  const counts = {
    all: all.length,
    url: all.filter((s) => s.tag === "url").length,
    ip: all.filter((s) => s.tag === "ip").length,
    path: all.filter((s) => s.tag === "path").length,
    base64: all.filter((s) => s.tag === "base64").length,
  };
  const filters = (["all", "url", "ip", "path", "base64"] as const)
    .map(
      (k) =>
        `<span class="chip ${S.stringFilter === k ? "active" : ""}" data-f="${k}">${k} ${counts[k]}</span>`
    )
    .join("");
  const filtered = all.filter((s) => S.stringFilter === "all" || s.tag === S.stringFilter);
  const rows = filtered
    .slice(0, 5000)
    .map(
      (s) =>
        `<div class="string-row"><span class="tag ${s.tag}">${s.tag}</span><span class="val">${esc(
          s.value
        )}</span><span class="cls" title="${esc(s.class)}">${esc(shortClass(s.class))}</span></div>`
    )
    .join("");
  host.innerHTML = `<div class="strings-filters">${filters}</div><div class="strings-list">${rows ||
    `<div style="padding:14px;color:var(--text-faint);font-size:11.5px">No strings match.</div>`}</div>`;
  host.querySelector(".strings-filters")!.addEventListener("click", (e) => {
    const c = (e.target as HTMLElement).closest(".chip") as HTMLElement;
    if (!c) return;
    S.stringFilter = c.dataset.f as typeof S.stringFilter;
    renderStrings();
  });
  for (const row of host.querySelectorAll<HTMLElement>(".string-row")) {
    const cls = row.querySelector(".cls")!.getAttribute("title")!;
    row.onclick = () => openClass(arc.info.id, cls);
  }
}

async function renderMetadata() {
  const arc = activeArchive();
  const host = $("#left-metadata");
  if (!arc) {
    host.innerHTML = `<div class="meta" style="color:var(--text-faint)">No archive open.</div>`;
    return;
  }
  if (!arc.metadata) {
    host.innerHTML = `<div class="meta" style="color:var(--text-faint)">Reading metadata…</div>`;
    try {
      arc.metadata = await api.getMetadata(arc.info.id);
    } catch (e) {
      host.innerHTML = `<div class="meta" style="color:var(--sev-high)">Couldn't read metadata:<br/>${esc(
        String(e)
      )}</div>`;
      toast(`Metadata failed: ${e}`, "error", 7000);
      return;
    }
  }
  const m = arc.metadata;
  if (!m) {
    host.innerHTML = `<div class="meta" style="color:var(--text-faint)">No metadata found.</div>`;
    return;
  }
  const kv = (k: string, v: string) =>
    v ? `<div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>` : "";
  const ul = (items: string[]) =>
    items.length ? `<ul>${items.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>` : "<div class='v' style='color:var(--text-faint)'>none</div>";

  let html = `<div class="meta">`;
  html += `<h3>Mod</h3><div class="kv">`;
  html += kv("Loader", m.loader || "unknown");
  html += kv("Mod id", m.modId);
  html += kv("Name", m.modName);
  html += kv("Version", m.version);
  html += kv("Description", m.description);
  html += `</div>`;
  if (m.authors.length) {
    html += `<h3>Authors</h3>${ul(m.authors)}`;
  }
  if (m.entrypoints.length) html += `<h3>Entry points</h3>${ul(m.entrypoints)}`;
  if (m.mixins.length) html += `<h3>Mixins</h3>${ul(m.mixins)}`;
  if (m.dependencies.length) html += `<h3>Dependencies</h3>${ul(m.dependencies)}`;
  if (m.manifest.length) {
    html += `<h3>MANIFEST.MF</h3><div class="kv">`;
    for (const [k, v] of m.manifest) html += kv(k, v);
    html += `</div>`;
  }
  for (const [path, content] of m.rawDescriptors) {
    html += `<h3>${esc(path)}</h3><pre>${esc(content.slice(0, 20000))}</pre>`;
  }
  html += `</div>`;
  host.innerHTML = html;
}

async function openResource(arc: OpenArchive, path: string) {
  S.active = arc.info.id;
  setLeftView("metadata");
  try {
    const content = await api.readResource(arc.info.id, path);
    const host = $("#left-metadata");
    host.innerHTML = `<div class="meta"><h3>${esc(path)}</h3><pre>${esc(
      content.slice(0, 200000)
    )}</pre></div>`;
  } catch (e) {
    toast(`Cannot read resource: ${e}`, "error", 7000);
  }
}

function exportMenu() {
  const arc = activeArchive();
  if (!arc) {
    toast("Open a mod first.", "error");
    return;
  }
  const b = $("#btn-export").getBoundingClientRect();
  showCtx(b.left, b.bottom + 3, [
    { label: "Decompiled source (.zip)", ico: "code", act: () => exportSourceZip() },
    { label: "Threat report (Markdown)", ico: "download", act: () => exportReport("markdown") },
    { label: "Threat report (JSON)", ico: "download", act: () => exportReport("json") },
  ]);
}

async function exportReport(fmt: "markdown" | "json") {
  const arc = activeArchive();
  if (!arc) return;
  if (!arc.analysis) {
    toast("Run Analyze first, then export the report.", "error");
    return;
  }
  const ext = fmt === "json" ? "json" : "md";
  const path = await saveDialog({
    defaultPath: `${baseName(arc)}-report.${ext}`,
    filters: [{ name: fmt === "json" ? "JSON" : "Markdown", extensions: [ext] }],
  });
  if (!path) return;
  try {
    const content = await api.exportReport(arc.info.id, fmt);
    await api.writeFile(path, content);
    setScan(`Saved ${fmt} report`);
    toast(`Saved ${fmt} report`, "ok");
  } catch (e) {
    toast(`Export failed: ${e}`, "error", 7000);
  }
}

async function exportSourceZip() {
  const arc = activeArchive();
  if (!arc) return;
  if (!S.java.usable) {
    toast("Java 17+ is required to decompile source for export.", "error", 7000);
    return;
  }
  const path = await saveDialog({
    defaultPath: `${baseName(arc)}-source.zip`,
    filters: [{ name: "Zip archive", extensions: ["zip"] }],
  });
  if (!path) return;
  setScan("Decompiling & zipping source…", undefined, true);
  toast("Decompiling all classes and zipping source…", "info");
  try {
    const n = await api.exportSources(arc.info.id, path);
    setScan(`Exported ${n} source files`, 100);
    toast(`Exported ${n} .java files to zip`, "ok");
  } catch (e) {
    setScan("Source export failed");
    toast(`Source export failed: ${e}`, "error", 8000);
  } finally {
    setTimeout(() => hideProgress(), 1200);
  }
}

function baseName(arc: OpenArchive): string {
  return arc.info.name.replace(/\.(jar|zip|class)$/i, "");
}

function wireGlobalSearch() {
  const overlay = $("#gsearch");
  const input = $<HTMLInputElement>("#gsearch-input");
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) overlay.classList.remove("show");
  });
  input.onkeydown = async (e) => {
    if (e.key === "Escape") overlay.classList.remove("show");
    if (e.key === "Enter") await doGlobalSearch(input.value);
  };
}

function openGlobalSearch(prefill = "") {
  const arc = activeArchive();
  if (!arc) return;
  $("#gsearch").classList.add("show");
  const input = $<HTMLInputElement>("#gsearch-input");
  input.value = prefill;
  input.focus();
  input.select();
  if (prefill) doGlobalSearch(prefill);
}

async function doGlobalSearch(q: string) {
  const arc = activeArchive();
  const results = $("#gsearch-results");
  if (!arc || !q.trim()) {
    results.innerHTML = "";
    return;
  }
  if (!arc.decompiledAll) {
    results.innerHTML = `<div class="placeholder" style="padding:14px;color:var(--text-faint);font-size:11.5px">Searching only decompiled classes. Run <b>Decompile all</b> for full coverage.</div>`;
  }
  try {
    const hits = await api.searchAll(arc.info.id, q, false);
    if (!hits.length) {
      results.innerHTML += `<div style="padding:14px;color:var(--text-faint);font-size:11.5px">No matches${
        arc.decompiledAll ? "." : " yet."
      }</div>`;
      return;
    }
    const ql = q.toLowerCase();
    results.innerHTML = hits
      .slice(0, 800)
      .map((h, i) => {
        const idx = h.text.toLowerCase().indexOf(ql);
        let text = esc(h.text);
        if (idx >= 0) {
          text =
            esc(h.text.slice(0, idx)) +
            "<em>" +
            esc(h.text.slice(idx, idx + q.length)) +
            "</em>" +
            esc(h.text.slice(idx + q.length));
        }
        const loc = h.line ? `${shortClass(h.class)}:${h.line}` : `${shortClass(h.class)} ·pool`;
        return `<div class="hit" data-i="${i}"><span class="where">${esc(
          loc
        )}</span><span class="text">${text}</span></div>`;
      })
      .join("");
    const arr = hits.slice(0, 800);
    for (const row of results.querySelectorAll<HTMLElement>(".hit")) {
      const h = arr[Number(row.dataset.i)];
      row.onclick = async () => {
        $("#gsearch").classList.remove("show");
        await openClass(arc.info.id, h.class);
        setTimeout(() => editor.jumpToLine(h.line), 60);
      };
    }
  } catch (e) {
    results.innerHTML = `<div style="padding:14px;color:var(--sev-high)">${esc(String(e))}</div>`;
  }
}

function showCtx(x: number, y: number, items: { label: string; ico: string; act: () => void }[]) {
  closeCtx();
  const menu = el(`<div class="ctx"></div>`);
  for (const it of items) {
    const row = el(`<div class="item">${icon(it.ico)}<span>${esc(it.label)}</span></div>`);
    row.onclick = (e) => {
      e.stopPropagation();
      closeCtx();
      it.act();
    };
    menu.appendChild(row);
  }
  document.body.appendChild(menu);
  const r = menu.getBoundingClientRect();
  menu.style.left = Math.min(x, window.innerWidth - r.width - 4) + "px";
  menu.style.top = Math.min(y, window.innerHeight - r.height - 4) + "px";
}
function closeCtx() {
  document.querySelector(".ctx")?.remove();
}

function classCtx(e: MouseEvent, archiveId: number, internalName: string) {
  e.preventDefault();
  const arc = S.archives.get(archiveId)!;
  showCtx(e.clientX, e.clientY, [
    { label: "Decompile (source)", ico: "code", act: () => openClassMode(archiveId, internalName, "source") },
    { label: "Show bytecode", ico: "binary", act: () => openClassMode(archiveId, internalName, "bytecode") },
    { label: "Scan this class", ico: "scan", act: () => scanClass(arc, internalName) },
    { label: "Copy name", ico: "copy", act: () => navigator.clipboard?.writeText(internalName.replace(/\//g, ".")) },
  ]);
}

function archiveCtx(e: MouseEvent, archiveId: number) {
  e.preventDefault();
  showCtx(e.clientX, e.clientY, [
    { label: "Decompile all", ico: "play", act: () => { S.active = archiveId; runDecompileAll(); } },
    { label: "Analyze", ico: "shield", act: () => { S.active = archiveId; runAnalyze(); } },
    { label: "Close archive", ico: "x", act: () => closeArchiveById(archiveId) },
  ]);
}

async function openClassMode(archiveId: number, internalName: string, mode: "source" | "bytecode") {
  await openClass(archiveId, internalName);
  if (S.activeTab >= 0) {
    S.tabs[S.activeTab].mode = mode;
    renderTabs();
    await loadCurrent();
  }
}

async function scanClass(arc: OpenArchive, internalName: string) {
  S.active = arc.info.id;
  await getDecompiled(arc, internalName, "source").catch(() => {});
  await runAnalyze();
  setLeftView("structure");
}

async function closeArchiveById(id: number) {
  try {
    await api.closeArchive(id);
  } catch {
  }
  S.archives.delete(id);
  S.order = S.order.filter((x) => x !== id);
  S.tabs = S.tabs.filter((t) => t.archiveId !== id);
  if (S.activeTab >= S.tabs.length) S.activeTab = S.tabs.length - 1;
  if (S.active === id) S.active = S.order[S.order.length - 1] ?? null;
  renderTree();
  renderTabs();
  renderThreat();
  if (S.activeTab >= 0) loadCurrent();
  updateToolbar();
  updateStatus();
}

function wireSplitters() {
  drag($("#split-left"), "--leftw", 180, 520, false, "#main");
  drag($("#split-right"), "--rightw", 240, 620, true, "#main");
  drag($("#dsplit-left"), "--leftw", 180, 560, false, "#dll-main");
  drag($("#dsplit-right"), "--rightw", 240, 620, true, "#dll-main");
}

function drag(
  handle: HTMLElement,
  varName: string,
  min: number,
  max: number,
  fromRight: boolean,
  containerSel: string
) {
  const main = $(containerSel);
  const saved = localStorage.getItem(`split${varName}`);
  if (saved) main.style.setProperty(varName, saved);
  handle.addEventListener("mousedown", (e) => {
    e.preventDefault();
    const move = (ev: MouseEvent) => {
      const rect = main.getBoundingClientRect();
      let w = fromRight ? rect.right - ev.clientX : ev.clientX - rect.left;
      w = Math.max(min, Math.min(max, w));
      main.style.setProperty(varName, `${w}px`);
    };
    const up = () => {
      document.removeEventListener("mousemove", move);
      document.removeEventListener("mouseup", up);
      localStorage.setItem(`split${varName}`, main.style.getPropertyValue(varName));
      document.body.style.cursor = "";
    };
    document.body.style.cursor = "col-resize";
    document.addEventListener("mousemove", move);
    document.addEventListener("mouseup", up);
  });
}

async function wireDragDrop() {
  await getCurrentWebview().onDragDropEvent((event) => {
    const p = event.payload;
    if (p.type !== "drop") return;
    const paths = p.paths || [];
    const bin = paths.find((x) => /\.(dll|exe|sys|ocx)$/i.test(x));
    if (bin) {
      setMode("dll");
      openDll(bin);
      return;
    }
    const arc = paths.find((x) => /\.(jar|zip|class)$/i.test(x));
    if (arc) {
      setMode("mod");
      openPath(arc);
    }
  });
}

function wireShortcuts() {
  wireModeButtons();
  window.addEventListener("keydown", (e) => {
    const mod = e.ctrlKey || e.metaKey;
    if (mod && e.key.toLowerCase() === "o") {
      e.preventDefault();
      if (S.mode === "dll") pickAndOpenDll();
      else if (S.mode === "mod") pickAndOpen();
    } else if (mod && e.shiftKey && e.key.toLowerCase() === "f" && S.mode === "mod") {
      e.preventDefault();
      openGlobalSearch($<HTMLInputElement>("#find").value);
    } else if (mod && e.key.toLowerCase() === "f") {
      e.preventDefault();
      (S.mode === "dll" ? dllEditor : editor).openSearch();
    } else if (mod && e.key.toLowerCase() === "w" && S.mode === "mod" && S.activeTab >= 0) {
      e.preventDefault();
      closeTab(S.activeTab);
    } else if (e.key === "Escape") {
      $("#gsearch").classList.remove("show");
      closeCtx();
    }
  });
}

async function addRecent(path: string) {
  if (!store) return;
  try {
    const list = ((await store.get<string[]>("recent")) || []).filter((p) => p !== path);
    list.unshift(path);
    await store.set("recent", list.slice(0, 10));
  } catch {
  }
}

function updateToolbar() {
  const arc = activeArchive();
  const on = !!arc;
  $("#btn-decompile-all").toggleAttribute("disabled", !on || !S.java.usable);
  $("#btn-analyze").toggleAttribute("disabled", !on || !S.java.usable);
  $("#btn-export").toggleAttribute("disabled", !on);
}

function updateStatus() {
  if (S.mode === "dll") {
    const r = S.dll?.report;
    $("#st-classes").innerHTML = r
      ? `<b>${esc(r.name)}</b> · ${r.kind} ${r.arch} · ${r.importCount} imports · ${r.sectionCount} sections`
      : "No binary";
    $("#st-engine").textContent = "PE static analysis";
    updateIdentity();
    return;
  }
  const arc = activeArchive();
  $("#st-classes").innerHTML = arc
    ? `<b>${esc(arc.info.name)}</b> · ${arc.info.classCount} classes · ${arc.info.resourceCount} resources`
    : "No archive";
  const tab = S.activeTab >= 0 ? S.tabs[S.activeTab] : null;
  $("#st-engine").textContent = tab ? `view: ${tab.mode}` : "Vineflower + CFR";
  updateIdentity();
}

function updateIdentity() {
  const idEl = $("#identity");
  if (S.mode === "dll" && S.dll?.report) {
    const r = S.dll.report;
    idEl.classList.add("show");
    idEl.innerHTML = `${icon("binary", "ico")}<span>Viewing <b>${esc(r.name)}</b> <span class="by">${esc(
      r.kind
    )} · ${esc(r.arch)}</span></span>`;
    idEl.title = `${r.name} (${r.kind} ${r.arch})`;
    return;
  }
  const arc = activeArchive();
  const m = arc?.metadata;
  if (S.mode !== "mod" || !arc || !m) {
    idEl.classList.remove("show");
    idEl.innerHTML = "";
    return;
  }
  const name = m.modName || m.modId || arc.info.name;
  const author = m.authors.length ? m.authors.join(", ") : "unknown author";
  idEl.classList.add("show");
  idEl.innerHTML = `${icon("cube", "ico")}<span>Viewing <b>${esc(name)}</b> <span class="by">by ${esc(
    author
  )}</span></span>`;
  idEl.title = `${name} by ${author}`;
}

function setTheme(patch: Partial<Theme>) {
  theme = { ...theme, ...patch };
  applyTheme(theme);
  saveTheme(theme);
}

function wireSettings() {
  const modal = $("#settings-modal");
  $("#btn-settings").onclick = () => openSettings();
  $("#settings-close").onclick = () => modal.classList.remove("show");
  $("#set-done").onclick = () => modal.classList.remove("show");
  modal.addEventListener("click", (e) => {
    if (e.target === modal) modal.classList.remove("show");
  });

  $<HTMLInputElement>("#set-accent").oninput = (e) =>
    setTheme({ accent: (e.target as HTMLInputElement).value, preset: "custom" });
  $<HTMLInputElement>("#set-text").oninput = (e) =>
    setTheme({ text: (e.target as HTMLInputElement).value, preset: "custom" });
  $<HTMLInputElement>("#set-bg-dim").oninput = (e) =>
    setTheme({ bgDim: Number((e.target as HTMLInputElement).value) / 100 });

  $("#set-bg-pick").onclick = () => pickBackground();
  $("#set-bg-clear").onclick = () => {
    setTheme({ bgImage: null });
    syncSettings();
  };
  $("#set-reset").onclick = () => {
    theme = { ...DEFAULT_THEME };
    applyTheme(theme);
    saveTheme(theme);
    syncSettings();
  };

  const row = $("#preset-row");
  row.innerHTML = PRESETS.map(
    (p) =>
      `<div class="swatch" data-p="${p.id}" title="${p.label}"><span style="background:${p.accent}"></span>${p.label}</div>`
  ).join("");
  row.addEventListener("click", (e) => {
    const s = (e.target as HTMLElement).closest(".swatch") as HTMLElement;
    if (!s) return;
    const p = PRESETS.find((x) => x.id === s.dataset.p)!;
    setTheme({ preset: p.id, accent: p.accent, text: p.text });
    syncSettings();
  });
}

function openSettings() {
  syncSettings();
  $("#settings-modal").classList.add("show");
}

function syncSettings() {
  $<HTMLInputElement>("#set-accent").value = theme.accent;
  $<HTMLInputElement>("#set-text").value = theme.text;
  $<HTMLInputElement>("#set-bg-dim").value = String(Math.round(theme.bgDim * 100));
  $("#bg-dim-row").style.display = theme.bgImage ? "flex" : "none";
  for (const s of document.querySelectorAll<HTMLElement>(".swatch"))
    s.classList.toggle("on", s.dataset.p === theme.preset);
}

async function pickBackground() {
  const sel = await openDialog({
    multiple: false,
    filters: [{ name: "Image", extensions: ["png", "jpg", "jpeg", "gif", "webp", "bmp"] }],
  });
  if (!sel) return;
  try {
    const url = await api.readImageDataUrl(sel as string);
    setTheme({ bgImage: url });
    syncSettings();
  } catch (e) {
    toast(`Couldn't load image: ${e}`, "error", 7000);
  }
}

function setMode(mode: "menu" | "mod" | "dll") {
  S.mode = mode;
  $("#menu-screen").style.display = mode === "menu" ? "flex" : "none";
  $("#main").style.display = mode === "mod" ? "grid" : "none";
  $("#dll-main").style.display = mode === "dll" ? "grid" : "none";
  $("#tb-mod").style.display = mode === "mod" ? "flex" : "none";
  $("#tb-dll").style.display = mode === "dll" ? "flex" : "none";
  $("#search-box").style.display = mode === "mod" ? "flex" : "none";
  $("#btn-menu").style.display = mode === "menu" ? "none" : "inline-flex";
  $("#brand-sub").textContent =
    mode === "dll" ? "PE / DLL analysis" : mode === "mod" ? "Minecraft mod analysis" : "forensic analysis";
  updateStatus();
}

function wireMenu() {
  $("#card-mod").onclick = () => {
    setMode("mod");
    pickAndOpen();
  };
  $("#card-dll").onclick = () => {
    setMode("dll");
    pickAndOpenDll();
  };
  $("#btn-menu").onclick = () => setMode("menu");
  $("#btn-open-dll").onclick = () => pickAndOpenDll();
  $("#btn-disasm").onclick = () => loadDisassembly();
  $("#btn-export-dll").onclick = () => exportDllReport();
  $("#dll-tabs").addEventListener("click", (e) => {
    const t = (e.target as HTMLElement).closest(".ptab") as HTMLElement;
    if (t) setDllView(t.dataset.dview as DllState["view"]);
  });
}

async function pickAndOpenDll() {
  const sel = await openDialog({
    multiple: false,
    filters: [{ name: "Native binary", extensions: ["dll", "exe", "sys", "ocx", "scr"] }],
  });
  if (!sel) return;
  await openDll(sel as string);
}

async function openDll(path: string) {
  setMode("dll");
  setScan("Analyzing PE…", undefined, true);
  try {
    const report = await api.analyzeDll(path);
    S.dll = { path, report, view: "info", stringFilter: "all", asmLoaded: false };
    $("#btn-export-dll").removeAttribute("disabled");
    $("#dll-empty .big").textContent = report.name;
    const codeBtn = $("#btn-disasm");
    codeBtn.removeAttribute("disabled");
    if (report.isDotnet) {
      codeBtn.innerHTML = `${icon("code")} Decompile (C#)`;
      codeBtn.onclick = () => loadDotnetSource();
      $("#dll-empty .small").innerHTML = "Managed .NET — press <b>Decompile (C#)</b> for readable source";
    } else {
      codeBtn.innerHTML = `${icon("binary")} Disassemble`;
      codeBtn.onclick = () => loadDisassembly();
      $("#dll-empty .small").innerHTML = "Press <b>Disassemble</b> to view x86/x64 code";
    }
    renderDllInfo();
    renderDllImports();
    renderDllThreat();
    setDllView("info");
    updateStatus();
    setScan(`Verdict: ${report.analysis.verdict.label}`, 100);
    toast(
      `${report.name} — ${report.analysis.verdict.label} (${report.analysis.findings.length} findings)`,
      report.analysis.verdict.level === "clean" ? "ok" : "info",
      5200
    );
    await addRecent(path);
  } catch (e) {
    setScan("PE analysis failed");
    toast(`DLL analysis failed: ${e}`, "error", 8000);
  } finally {
    setTimeout(() => hideProgress(), 1200);
  }
}

function setDllView(view: DllState["view"]) {
  if (!S.dll) return;
  S.dll.view = view;
  for (const t of document.querySelectorAll<HTMLElement>(".ptab[data-dview]"))
    t.classList.toggle("active", t.dataset.dview === view);
  $("#dll-info").classList.toggle("hidden", view !== "info");
  $("#dll-imports").classList.toggle("hidden", view !== "imports");
  $("#dll-strings").classList.toggle("hidden", view !== "strings");
  if (view === "strings") renderDllStrings();
}

function renderDllInfo() {
  const r = S.dll?.report;
  if (!r) return;
  const kv = (k: string, v: string) =>
    v ? `<div class="k">${esc(k)}</div><div class="v">${v}</div>` : "";
  let h = `<div class="pe"><h3>Binary</h3><div class="kv">`;
  h += kv("File", esc(r.name));
  h += kv("Type", `${esc(r.kind)} · ${esc(r.arch)}`);
  h += kv("Subsystem", esc(r.subsystem));
  h += kv("Managed", r.isDotnet ? `.NET / CLR <span class="tagdot">decompilable</span>` : "Native");
  h += kv(
    "Signed",
    r.signed ? `<span style="color:var(--ok)">yes</span> · verify publisher` : `<span style="color:var(--text-dim)">no</span>`
  );
  h += kv("Compiled", esc(r.timestamp) || "unknown");
  h += kv("Image size", fmtSize(r.imageSize));
  h += kv("Entry point", `0x${r.entryPoint.toString(16)}`);
  h += kv("Imports", `${r.importCount} from ${r.imports.length} DLLs`);
  h += kv("Exports", String(r.exportCount));
  h += kv("Strings", String(r.stringCount));
  h += `</div>`;

  h += `<h3>Sections (${r.sections.length})</h3><table class="sec-table"><tr><th>Name</th><th>Perms</th><th>Raw</th><th class="ent">Entropy</th></tr>`;
  for (const s of r.sections) {
    const pct = Math.min(100, (s.entropy / 8) * 100);
    const hi = s.entropy > 7 ? "high" : "";
    h += `<tr class="${s.suspicious ? "bad" : ""}"><td>${esc(s.name)}</td><td>${esc(
      s.perms
    )}</td><td>${fmtSize(s.rawSize)}</td><td class="ent">${s.entropy.toFixed(
      2
    )}<span class="entropy-bar ${hi}"><i style="width:${pct}%"></i></span></td></tr>`;
  }
  h += `</table>`;

  if (r.exports.length) {
    h += `<h3>Exports (${r.exports.length})</h3><div style="font-family:var(--mono-font);font-size:11px;color:var(--text-dim);line-height:1.7">`;
    h += r.exports.slice(0, 400).map((e) => esc(e)).join("<br/>");
    if (r.exports.length > 400) h += `<br/>… +${r.exports.length - 400} more`;
    h += `</div>`;
  }
  h += `</div>`;
  $("#dll-info").innerHTML = h;
}

function renderDllImports() {
  const r = S.dll?.report;
  if (!r) return;
  $("#dc-imports").textContent = String(r.importCount || "");
  const host = $("#dll-imports");
  host.innerHTML = "";
  if (!r.imports.length) {
    host.innerHTML = `<div style="padding:14px;color:var(--text-faint);font-size:11.5px">No static imports (the binary may be packed).</div>`;
    return;
  }
  for (const imp of r.imports) {
    renderImportGroup(host, imp);
  }
}

function renderImportGroup(host: HTMLElement, imp: PeImport) {
  const open = imp.flagged > 0;
  const group = el(`<div class="imp-group"></div>`);
  const head = el(
    `<div class="imp-dll"><span class="twist">${open ? "▾" : "▸"}</span>${icon(
      "file",
      "ico"
    )}<span>${esc(imp.dll)}</span>${
      imp.flagged ? `<span class="flag">▲ ${imp.flagged}</span>` : ""
    }<span class="cnt">${imp.functions.length}</span></div>`
  );
  const body = el(`<div class="imp-funcs" ${open ? "" : 'style="display:none"'}></div>`);
  body.innerHTML = imp.functions
    .map((f) => `<div class="imp-func ${isDangerApi(f) ? "danger" : ""}">${esc(f)}</div>`)
    .join("");
  head.onclick = () => {
    const shown = body.style.display !== "none";
    body.style.display = shown ? "none" : "block";
    head.querySelector(".twist")!.textContent = shown ? "▸" : "▾";
  };
  group.appendChild(head);
  group.appendChild(body);
  host.appendChild(group);
}

const DANGER_APIS = [
  "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "NtCreateThreadEx",
  "SetThreadContext", "RtlCreateUserThread", "SetWindowsHookEx", "GetAsyncKeyState",
  "URLDownloadToFile", "WinHttpOpen", "InternetOpen", "ShellExecute", "WinExec",
  "CreateProcess", "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "AdjustTokenPrivileges",
  "CryptEncrypt", "CryptDecrypt", "CreateService", "BitBlt", "VirtualProtect",
];
const isDangerApi = (f: string) => DANGER_APIS.some((d) => f.includes(d));

async function renderDllStrings() {
  const r = S.dll;
  if (!r) return;
  const host = $("#dll-strings");
  if (!r.strings) {
    host.innerHTML = `<div class="strings-filters"></div><div style="padding:14px;color:var(--text-faint);font-size:11.5px">Extracting strings…</div>`;
    try {
      r.strings = await api.getDllStrings(r.path);
    } catch (e) {
      host.innerHTML = `<div style="padding:14px;color:var(--sev-high);font-size:11.5px">${esc(String(e))}</div>`;
      return;
    }
  }
  const all = r.strings;
  $("#dc-strings").textContent = String(all.length || "");
  const counts = {
    all: all.length,
    url: all.filter((s) => s.tag === "url").length,
    ip: all.filter((s) => s.tag === "ip").length,
    path: all.filter((s) => s.tag === "path").length,
    base64: all.filter((s) => s.tag === "base64").length,
  };
  const filters = (["all", "url", "ip", "path", "base64"] as const)
    .map(
      (k) =>
        `<span class="chip ${r.stringFilter === k ? "active" : ""}" data-f="${k}">${k} ${counts[k]}</span>`
    )
    .join("");
  const filtered = all.filter((s) => r.stringFilter === "all" || s.tag === r.stringFilter);
  const rows = filtered
    .slice(0, 6000)
    .map(
      (s) =>
        `<div class="string-row"><span class="tag ${s.tag}">${s.tag}</span><span class="val">${esc(
          s.value
        )}</span></div>`
    )
    .join("");
  host.innerHTML = `<div class="strings-filters">${filters}</div><div class="strings-list">${
    rows || `<div style="padding:14px;color:var(--text-faint);font-size:11.5px">No strings match.</div>`
  }</div>`;
  host.querySelector(".strings-filters")!.addEventListener("click", (e) => {
    const c = (e.target as HTMLElement).closest(".chip") as HTMLElement;
    if (!c) return;
    r.stringFilter = c.dataset.f as DllState["stringFilter"];
    renderDllStrings();
  });
}

function renderDllThreat() {
  const r = S.dll?.report;
  const verdictEl = $("#dll-verdict");
  const list = $("#dll-findings");
  if (!r) {
    verdictEl.style.display = "none";
    list.innerHTML = `<div class="placeholder">Open a DLL/EXE to analyze.</div>`;
    return;
  }
  renderVerdictInto(verdictEl, r.analysis, "scan");
  renderFindingsInto(list, r.analysis, (f) => {
    setDllView(f.id.startsWith("pe-") ? "imports" : "strings");
  });
}

async function loadDisassembly() {
  if (!S.dll) return;
  $("#dll-empty").style.display = "none";
  $("#dll-editor-host").style.display = "block";
  $("#dll-asm-bar").style.display = "flex";
  $("#dll-asm-engine").textContent = "x86/x64 disassembly";
  $("#dll-asm-note").textContent = "disassembling…";
  try {
    const asm = await api.disassembleDll(S.dll.path);
    dllEditor.setDoc(asm, "bytecode");
    $("#dll-asm-note").textContent = "";
    S.dll.asmLoaded = true;
  } catch (e) {
    $("#dll-asm-note").textContent = String(e);
    toast(`Disassembly failed: ${e}`, "error", 7000);
  }
}

async function loadDotnetSource() {
  if (!S.dll) return;
  $("#dll-empty").style.display = "none";
  $("#dll-editor-host").style.display = "block";
  $("#dll-asm-bar").style.display = "flex";
  $("#dll-asm-engine").textContent = "C# · ILSpy";
  $("#dll-asm-note").textContent = "decompiling .NET → C#…";
  setScan("Decompiling .NET…", undefined, true);
  try {
    const cs = await api.decompileDotnet(S.dll.path);
    dllEditor.setDoc(cs, "java"); // Java mode highlights C# well enough
    $("#dll-asm-note").textContent = "";
    setScan("Decompiled .NET", 100);
  } catch (e) {
    $("#dll-asm-note").textContent = String(e);
    toast(`.NET decompile failed: ${e}`, "error", 9000);
    setScan("Decompile failed");
  } finally {
    setTimeout(() => hideProgress(), 1200);
  }
}

async function exportDllReport() {
  const r = S.dll?.report;
  if (!r) return;
  const path = await saveDialog({
    defaultPath: `${r.name.replace(/\.(dll|exe|sys|ocx)$/i, "")}-pe-report.md`,
    filters: [
      { name: "Markdown", extensions: ["md"] },
      { name: "JSON", extensions: ["json"] },
    ],
  });
  if (!path) return;
  const asJson = path.toLowerCase().endsWith(".json");
  const content = asJson ? JSON.stringify(r, null, 2) : dllMarkdown(r);
  try {
    await api.writeFile(path, content);
    toast(`Saved PE report`, "ok");
  } catch (e) {
    toast(`Export failed: ${e}`, "error", 7000);
  }
}

function dllMarkdown(r: DllReport): string {
  let o = `# End Decompiler PE Report — ${r.name}\n\n`;
  o += `- **Path:** \`${r.path}\`\n- **Type:** ${r.kind} ${r.arch}\n- **Subsystem:** ${r.subsystem}\n`;
  o += `- **.NET:** ${r.isDotnet}\n- **Compiled:** ${r.timestamp}\n`;
  o += `- **Verdict:** ${r.analysis.verdict.label} (score ${r.analysis.verdict.score})\n\n> ${r.analysis.verdict.reasoning}\n\n`;
  o += `## Sections\n\n| Name | Perms | Raw | Entropy |\n|---|---|---|---|\n`;
  for (const s of r.sections)
    o += `| ${s.name} | ${s.perms} | ${s.rawSize} | ${s.entropy.toFixed(2)}${s.suspicious ? " ⚠" : ""} |\n`;
  o += `\n## Findings\n\n`;
  if (!r.analysis.findings.length) o += `_No suspicious patterns._\n`;
  else {
    o += `| Severity | Category | Why | Snippet |\n|---|---|---|---|\n`;
    for (const f of r.analysis.findings)
      o += `| ${f.severity} | ${f.category} | ${f.why.replace(/\|/g, "\\|")} | \`${f.snippet.replace(/\|/g, "\\|")}\` |\n`;
  }
  o += `\n## Imports\n\n`;
  for (const imp of r.imports) o += `- **${imp.dll}** (${imp.functions.length}${imp.flagged ? `, ${imp.flagged} flagged` : ""})\n`;
  return o;
}

function setScan(text: string, pct?: number, show = false) {
  S.scan = text;
  $("#st-scan-text").textContent = text;
  const prog = $("#st-progress");
  if (show || pct != null) {
    prog.style.display = "block";
    if (pct != null) $("#st-bar").style.width = `${pct}%`;
  }
}
function hideProgress() {
  $("#st-progress").style.display = "none";
  $("#st-bar").style.width = "0%";
  setScan("Ready");
}

init();
