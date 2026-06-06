
use crate::model::*;
use crate::{analysis, archive, decompile, java, metadata, pe};
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};

const SINGLE_TIMEOUT: Duration = Duration::from_secs(30);
const JAVAP_TIMEOUT: Duration = Duration::from_secs(20);
const BATCH_TIMEOUT: Duration = Duration::from_secs(150);

struct Session {
    archive: archive::OpenedArchive,
    source_cache: HashMap<String, DecompileResult>,
    bytecode_cache: HashMap<String, String>,
    strings: Option<Vec<StringEntry>>,
    metadata: Option<Metadata>,
    analysis: Option<AnalysisReport>,
}

pub struct AppState {
    sessions: Mutex<HashMap<u64, Session>>,
    next_id: AtomicU64,
    java: Mutex<JavaInfo>,
    vineflower_jar: PathBuf,
    cfr_jar: PathBuf,
    ilspy_dir: PathBuf,
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(vineflower_jar: PathBuf, cfr_jar: PathBuf, ilspy_dir: PathBuf) -> Self {
        AppState {
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            java: Mutex::new(java::detect()),
            vineflower_jar,
            cfr_jar,
            ilspy_dir,
        }
    }
    fn java_info(&self) -> JavaInfo {
        self.java.lock().clone()
    }
}

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

#[tauri::command]
pub fn detect_java(state: State<'_, Shared>) -> JavaInfo {
    let fresh = java::detect();
    *state.java.lock() = fresh.clone();
    fresh
}

#[tauri::command]
pub async fn open_archive(state: State<'_, Shared>, path: String) -> Result<ArchiveInfo, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || open_archive_impl(&st, &path))
        .await
        .map_err(err)?
}

fn open_archive_impl(st: &AppState, path: &str) -> Result<ArchiveInfo, String> {
    let opened = archive::open(Path::new(path)).map_err(err)?;
    let id = st.next_id.fetch_add(1, Ordering::SeqCst);
    let info = ArchiveInfo {
        id,
        name: opened.name.clone(),
        path: opened.original.to_string_lossy().into_owned(),
        class_count: opened.classes.len(),
        resource_count: opened.resources.len(),
        total_size: opened.total_size,
        classes: opened.classes.clone(),
        resources: opened.resources.clone(),
    };
    st.sessions.lock().insert(
        id,
        Session {
            archive: opened,
            source_cache: HashMap::new(),
            bytecode_cache: HashMap::new(),
            strings: None,
            metadata: None,
            analysis: None,
        },
    );
    Ok(info)
}

#[tauri::command]
pub fn close_archive(state: State<'_, Shared>, id: u64) {
    state.sessions.lock().remove(&id);
}

struct Paths {
    classes_root: PathBuf,
}

fn paths_for(st: &AppState, id: u64) -> Result<Paths, String> {
    let sessions = st.sessions.lock();
    let s = sessions.get(&id).ok_or("archive not open")?;
    Ok(Paths {
        classes_root: s.archive.classes_root.clone(),
    })
}

#[tauri::command]
pub async fn decompile_class(
    state: State<'_, Shared>,
    id: u64,
    internal_name: String,
    mode: String,
) -> Result<DecompileResult, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || decompile_class_impl(&st, id, &internal_name, &mode))
        .await
        .map_err(err)?
}

fn decompile_class_impl(
    st: &AppState,
    id: u64,
    internal_name: &str,
    mode: &str,
) -> Result<DecompileResult, String> {
    let java = st.java_info();
    if !java.usable {
        return Err(format!("Java 17+ is required. {}", java.note));
    }
    let paths = paths_for(st, id)?;
    let outer = internal_name.split('$').next().unwrap_or(internal_name).to_string();

    if mode == "bytecode" {
        if let Some(code) = st
            .sessions
            .lock()
            .get(&id)
            .and_then(|s| s.bytecode_cache.get(internal_name).cloned())
        {
            return Ok(bytecode_result(internal_name, code));
        }
        let javap = java::javap_for(&java.java_path);
        let code = decompile::javap(&javap, &paths.classes_root, internal_name, JAVAP_TIMEOUT)
            .map_err(err)?;
        if let Some(s) = st.sessions.lock().get_mut(&id) {
            s.bytecode_cache.insert(internal_name.to_string(), code.clone());
        }
        return Ok(bytecode_result(internal_name, code));
    }

    if let Some(cached) = st
        .sessions
        .lock()
        .get(&id)
        .and_then(|s| s.source_cache.get(&outer).cloned())
    {
        return Ok(cached);
    }

    let result = decompile_source(st, &java.java_path, &paths.classes_root, &outer);
    if let Some(s) = st.sessions.lock().get_mut(&id) {
        s.source_cache.insert(outer.clone(), result.clone());
    }
    Ok(result)
}

fn decompile_source(
    st: &AppState,
    java_path: &str,
    classes_root: &Path,
    outer: &str,
) -> DecompileResult {
    let vf_err = match decompile::vineflower_single(
        java_path,
        &st.vineflower_jar,
        classes_root,
        outer,
        SINGLE_TIMEOUT,
    ) {
        Ok(src) => {
            return DecompileResult {
                internal_name: outer.into(),
                mode: "source".into(),
                language: "java".into(),
                code: src,
                decompiler: "vineflower".into(),
                fell_back: false,
                note: String::new(),
            }
        }
        Err(e) => e.to_string(),
    };
    let cfr_err = match decompile::cfr_single(java_path, &st.cfr_jar, classes_root, outer, SINGLE_TIMEOUT)
    {
        Ok(src) => {
            return DecompileResult {
                internal_name: outer.into(),
                mode: "source".into(),
                language: "java".into(),
                code: src,
                decompiler: "cfr".into(),
                fell_back: true,
                note: format!("Vineflower failed ({vf_err}); showing CFR output."),
            }
        }
        Err(e) => e.to_string(),
    };
    let diag = format!(
        "// End Decompiler: both decompilers failed for {outer}; showing bytecode.\n\
         //   jars: vineflower={} | cfr={}\n\
         //   Vineflower error: {vf_err}\n\
         //   CFR error: {cfr_err}\n\n",
        st.vineflower_jar.display(),
        st.cfr_jar.display(),
    );
    let javap = java::javap_for(java_path);
    match decompile::javap(&javap, classes_root, outer, JAVAP_TIMEOUT) {
        Ok(code) => DecompileResult {
            internal_name: outer.into(),
            mode: "source".into(),
            language: "bytecode".into(),
            code: format!("{diag}{code}"),
            decompiler: "javap".into(),
            fell_back: true,
            note: "Both decompilers failed; showing raw bytecode (see top of view for why).".into(),
        },
        Err(e) => DecompileResult {
            internal_name: outer.into(),
            mode: "source".into(),
            language: "java".into(),
            code: format!("{diag}// javap also failed: {e}\n"),
            decompiler: "none".into(),
            fell_back: true,
            note: "Decompilation failed.".into(),
        },
    }
}

fn bytecode_result(internal_name: &str, code: String) -> DecompileResult {
    DecompileResult {
        internal_name: internal_name.into(),
        mode: "bytecode".into(),
        language: "bytecode".into(),
        code,
        decompiler: "javap".into(),
        fell_back: false,
        note: String::new(),
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Progress {
    id: u64,
    done: usize,
    total: usize,
    current: String,
}

#[tauri::command]
pub async fn decompile_all(
    app: AppHandle,
    state: State<'_, Shared>,
    id: u64,
) -> Result<usize, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || decompile_all_impl(&app, &st, id))
        .await
        .map_err(err)?
}

fn decompile_all_impl(app: &AppHandle, st: &AppState, id: u64) -> Result<usize, String> {
    let java = st.java_info();
    if !java.usable {
        return Err(format!("Java 17+ is required. {}", java.note));
    }
    let (classes_root, total) = {
        let sessions = st.sessions.lock();
        let s = sessions.get(&id).ok_or("archive not open")?;
        let total = s
            .archive
            .classes
            .iter()
            .filter(|c| !c.inner)
            .count()
            .max(1);
        (s.archive.classes_root.clone(), total)
    };

    let out_dir = tempfile::tempdir().map_err(err)?;
    let mut done = 0usize;
    let app_cl = app.clone();
    decompile::vineflower_all(
        &java.java_path,
        &st.vineflower_jar,
        &classes_root,
        out_dir.path(),
        BATCH_TIMEOUT,
        move |current| {
            done += 1;
            let _ = app_cl.emit(
                "decompile-progress",
                Progress {
                    id,
                    done: done.min(total),
                    total,
                    current,
                },
            );
        },
    )
    .map_err(err)?;

    let sources = decompile::collect_sources(out_dir.path()).map_err(err)?;
    let mut count = 0usize;
    if let Some(s) = st.sessions.lock().get_mut(&id) {
        for (internal, code) in sources {
            if decompile::is_decompiler_stub(&code) {
                continue;
            }
            count += 1;
            s.source_cache.entry(internal.clone()).or_insert(DecompileResult {
                internal_name: internal,
                mode: "source".into(),
                language: "java".into(),
                code,
                decompiler: "vineflower".into(),
                fell_back: false,
                note: String::new(),
            });
        }
    }
    let _ = app.emit(
        "decompile-progress",
        Progress {
            id,
            done: total,
            total,
            current: "done".into(),
        },
    );
    Ok(count)
}

#[tauri::command]
pub async fn get_strings(state: State<'_, Shared>, id: u64) -> Result<Vec<StringEntry>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        if let Some(cached) = st.sessions.lock().get(&id).and_then(|s| s.strings.clone()) {
            return Ok(cached);
        }
        let (root, classes) = {
            let sessions = st.sessions.lock();
            let s = sessions.get(&id).ok_or("archive not open")?;
            (s.archive.classes_root.clone(), s.archive.classes.clone())
        };
        let strings = archive::extract_strings(&root, &classes);
        if let Some(s) = st.sessions.lock().get_mut(&id) {
            s.strings = Some(strings.clone());
        }
        Ok(strings)
    })
    .await
    .map_err(err)?
}

#[tauri::command]
pub async fn get_metadata(state: State<'_, Shared>, id: u64) -> Result<Metadata, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        if let Some(cached) = st.sessions.lock().get(&id).and_then(|s| s.metadata.clone()) {
            return Ok(cached);
        }
        let (root, resources) = {
            let sessions = st.sessions.lock();
            let s = sessions.get(&id).ok_or("archive not open")?;
            (s.archive.classes_root.clone(), s.archive.resources.clone())
        };
        let md = metadata::parse(&root, &resources);
        if let Some(s) = st.sessions.lock().get_mut(&id) {
            s.metadata = Some(md.clone());
        }
        Ok(md)
    })
    .await
    .map_err(err)?
}

#[tauri::command]
pub async fn read_resource(state: State<'_, Shared>, id: u64, path: String) -> Result<String, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let root = {
            let sessions = st.sessions.lock();
            sessions
                .get(&id)
                .ok_or("archive not open")?
                .archive
                .classes_root
                .clone()
        };
        let safe: PathBuf = path.split(['/', '\\']).filter(|c| *c != "..").collect();
        let full = root.join(safe);
        std::fs::read_to_string(&full).map_err(err)
    })
    .await
    .map_err(err)?
}

#[tauri::command]
pub async fn analyze_archive(state: State<'_, Shared>, id: u64) -> Result<AnalysisReport, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || analyze_impl(&st, id))
        .await
        .map_err(err)?
}

fn analyze_impl(st: &AppState, id: u64) -> Result<AnalysisReport, String> {
    let (root, classes, resources, sources) = {
        let sessions = st.sessions.lock();
        let s = sessions.get(&id).ok_or("archive not open")?;
        let sources: HashMap<String, String> = s
            .source_cache
            .iter()
            .map(|(k, v)| (k.clone(), v.code.clone()))
            .collect();
        (
            s.archive.classes_root.clone(),
            s.archive.classes.clone(),
            s.archive.resources.clone(),
            sources,
        )
    };

    let mut symbols: HashMap<String, String> = HashMap::new();
    for c in &classes {
        let outer = c.internal_name.split('$').next().unwrap_or(&c.internal_name).to_string();
        let blob = archive::extract_symbols(&root, &c.internal_name);
        symbols.entry(outer).or_default().push_str(&blob);
    }

    let mut res_heads: Vec<(String, Vec<u8>)> = Vec::new();
    for r in &resources {
        let safe: PathBuf = r.path.split(['/', '\\']).filter(|c| *c != "..").collect();
        if let Ok(mut f) = std::fs::File::open(root.join(safe)) {
            use std::io::Read;
            let mut head = [0u8; 16];
            if let Ok(n) = f.read(&mut head) {
                res_heads.push((r.path.clone(), head[..n].to_vec()));
            }
        }
    }

    let class_names: Vec<String> = classes.iter().map(|c| c.internal_name.clone()).collect();
    let report = analysis::analyze(&sources, &symbols, &res_heads, &class_names);
    if let Some(s) = st.sessions.lock().get_mut(&id) {
        s.analysis = Some(report.clone());
    }
    Ok(report)
}

#[tauri::command]
pub async fn search_all(
    state: State<'_, Shared>,
    id: u64,
    query: String,
    case_sensitive: bool,
) -> Result<Vec<SearchHit>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        if query.trim().is_empty() {
            return Ok(Vec::new());
        }
        let (sources, root, classes) = {
            let sessions = st.sessions.lock();
            let s = sessions.get(&id).ok_or("archive not open")?;
            let sources: HashMap<String, String> = s
                .source_cache
                .iter()
                .map(|(k, v)| (k.clone(), v.code.clone()))
                .collect();
            (sources, s.archive.classes_root.clone(), s.archive.classes.clone())
        };
        let needle = if case_sensitive { query.clone() } else { query.to_lowercase() };
        let hay_of = |s: &str| if case_sensitive { s.to_string() } else { s.to_lowercase() };
        let mut hits = Vec::new();

        for (class, code) in &sources {
            for (i, line) in code.lines().enumerate() {
                if hay_of(line).contains(&needle) {
                    hits.push(SearchHit {
                        class: class.clone(),
                        line: (i + 1) as u32,
                        text: line.trim().chars().take(200).collect(),
                    });
                    if hits.len() >= 4000 {
                        return Ok(hits);
                    }
                }
            }
        }
        for c in &classes {
            let outer = c.internal_name.split('$').next().unwrap_or(&c.internal_name);
            if sources.contains_key(outer) {
                continue;
            }
            for entry in archive::extract_symbols(&root, &c.internal_name).lines() {
                if hay_of(entry).contains(&needle) {
                    hits.push(SearchHit {
                        class: outer.to_string(),
                        line: 0,
                        text: entry.trim().chars().take(200).collect(),
                    });
                    if hits.len() >= 4000 {
                        return Ok(hits);
                    }
                }
            }
        }
        Ok(hits)
    })
    .await
    .map_err(err)?
}

#[tauri::command]
pub async fn export_report(
    state: State<'_, Shared>,
    id: u64,
    format: String,
) -> Result<String, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let sessions = st.sessions.lock();
        let s = sessions.get(&id).ok_or("archive not open")?;
        let report = s.analysis.clone().ok_or("run analysis first")?;
        let md = s.metadata.clone().unwrap_or_default();
        let name = s.archive.name.clone();
        let path = s.archive.original.to_string_lossy().into_owned();
        drop(sessions);
        if format == "json" {
            Ok(report_json(&name, &path, &report, &md))
        } else {
            Ok(report_markdown(&name, &path, &report, &md))
        }
    })
    .await
    .map_err(err)?
}

fn report_json(name: &str, path: &str, report: &AnalysisReport, md: &Metadata) -> String {
    let v = serde_json::json!({
        "tool": "End Decompiler",
        "archive": { "name": name, "path": path },
        "verdict": report.verdict,
        "classesScanned": report.classes_scanned,
        "severityCounts": report.severity_counts,
        "categoryCounts": report.category_counts,
        "findings": report.findings,
        "metadata": md,
    });
    serde_json::to_string_pretty(&v).unwrap_or_default()
}

fn report_markdown(name: &str, path: &str, report: &AnalysisReport, md: &Metadata) -> String {
    let mut out = String::new();
    out.push_str(&format!("# End Decompiler Report — {name}\n\n"));
    out.push_str(&format!("- **Archive:** `{path}`\n"));
    out.push_str(&format!(
        "- **Verdict:** {} (score {})\n",
        report.verdict.label, report.verdict.score
    ));
    out.push_str(&format!("- **Classes scanned:** {}\n", report.classes_scanned));
    if !md.loader.is_empty() {
        out.push_str(&format!("- **Loader:** {}\n", md.loader));
    }
    if !md.mod_id.is_empty() {
        out.push_str(&format!("- **Mod id:** {} {}\n", md.mod_id, md.version));
    }
    out.push_str(&format!("\n> {}\n\n", report.verdict.reasoning));

    out.push_str("## Severity summary\n\n");
    for (sev, n) in &report.severity_counts {
        out.push_str(&format!("- {sev}: {n}\n"));
    }
    out.push('\n');

    out.push_str("## Findings\n\n");
    if report.findings.is_empty() {
        out.push_str("_No suspicious patterns detected._\n\n");
    } else {
        out.push_str("| Severity | Category | Class | Line | Why | Snippet |\n");
        out.push_str("|---|---|---|---|---|---|\n");
        for f in &report.findings {
            let snippet = f.snippet.replace('|', "\\|").replace('\n', " ");
            let why = f.why.replace('|', "\\|");
            out.push_str(&format!(
                "| {} | {} | `{}` | {} | {} | `{}` |\n",
                f.severity.as_str(),
                f.category,
                f.class,
                f.line,
                why,
                snippet
            ));
        }
        out.push('\n');
    }

    if !md.manifest.is_empty() {
        out.push_str("## Manifest\n\n");
        for (k, v) in &md.manifest {
            out.push_str(&format!("- **{k}:** {v}\n"));
        }
    }
    out
}

#[tauri::command]
pub async fn export_sources(
    state: State<'_, Shared>,
    id: u64,
    dest: String,
) -> Result<usize, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || export_sources_impl(&st, id, &dest))
        .await
        .map_err(err)?
}

fn export_sources_impl(st: &AppState, id: u64, dest: &str) -> Result<usize, String> {
    use std::io::Write;

    let java = st.java_info();
    if !java.usable {
        return Err(format!("Java 17+ is required to decompile source. {}", java.note));
    }
    let (classes_root, cached) = {
        let sessions = st.sessions.lock();
        let s = sessions.get(&id).ok_or("archive not open")?;
        let cached: HashMap<String, String> = s
            .source_cache
            .iter()
            .filter(|(_, v)| v.language == "java")
            .map(|(k, v)| (k.clone(), v.code.clone()))
            .collect();
        (s.archive.classes_root.clone(), cached)
    };

    let out = tempfile::tempdir().map_err(err)?;
    decompile::vineflower_all(
        &java.java_path,
        &st.vineflower_jar,
        &classes_root,
        out.path(),
        BATCH_TIMEOUT,
        |_| {},
    )
    .map_err(err)?;

    let mut map: HashMap<String, String> = HashMap::new();
    for (internal, code) in decompile::collect_sources(out.path()).map_err(err)? {
        if !decompile::is_decompiler_stub(&code) {
            map.insert(internal, code);
        }
    }
    for (k, v) in cached {
        map.insert(k, v);
    }
    if map.is_empty() {
        return Err("no source could be decompiled".into());
    }

    let file = std::fs::File::create(dest).map_err(err)?;
    let mut zip = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let mut entries: Vec<(String, String)> = map.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut count = 0usize;
    for (internal, src) in entries {
        let safe = internal.replace('\\', "/");
        if safe.contains("..") {
            continue;
        }
        zip.start_file(format!("{safe}.java"), opts).map_err(err)?;
        zip.write_all(src.as_bytes()).map_err(err)?;
        count += 1;
    }
    zip.finish().map_err(err)?;
    Ok(count)
}

#[tauri::command]
pub async fn analyze_dll(path: String) -> Result<crate::model::DllReport, String> {
    tauri::async_runtime::spawn_blocking(move || pe::analyze_path(Path::new(&path)).map_err(err))
        .await
        .map_err(err)?
}

#[tauri::command]
pub async fn get_dll_strings(path: String) -> Result<Vec<StringEntry>, String> {
    tauri::async_runtime::spawn_blocking(move || pe::strings_of(Path::new(&path)).map_err(err))
        .await
        .map_err(err)?
}

#[tauri::command]
pub async fn disassemble_dll(path: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || pe::disassemble(Path::new(&path)).map_err(err))
        .await
        .map_err(err)?
}

#[tauri::command]
pub async fn decompile_dotnet(state: State<'_, Shared>, path: String) -> Result<String, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let dotnet = pe::detect_dotnet().ok_or(
            "No .NET runtime found. Install the .NET 6+ runtime to decompile .NET assemblies (https://dotnet.microsoft.com/download).",
        )?;
        pe::decompile_dotnet(
            &dotnet,
            &st.ilspy_dir,
            Path::new(&path),
            Duration::from_secs(180),
        )
        .map_err(err)
    })
    .await
    .map_err(err)?
}

#[tauri::command]
pub async fn read_image_data_url(path: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        use base64::Engine;
        let bytes = std::fs::read(&path).map_err(err)?;
        if bytes.len() > 24 * 1024 * 1024 {
            return Err("image too large (max 24 MB)".into());
        }
        let mime = match Path::new(&path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str()
        {
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "gif" => "image/gif",
            "webp" => "image/webp",
            "bmp" => "image/bmp",
            _ => "image/png",
        };
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        Ok(format!("data:{mime};base64,{b64}"))
    })
    .await
    .map_err(err)?
}

#[tauri::command]
pub async fn write_file(path: String, content: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || std::fs::write(&path, content).map_err(err))
        .await
        .map_err(err)?
}

pub fn resolve_jars(app: &AppHandle) -> (PathBuf, PathBuf) {
    let vf = strip_verbatim(find_jar(app, "vineflower.jar"));
    let cfr = strip_verbatim(find_jar(app, "cfr.jar"));
    eprintln!(
        "[endecompiler] decompilers: vineflower={} (exists={}), cfr={} (exists={})",
        vf.display(),
        vf.exists(),
        cfr.display(),
        cfr.exists()
    );
    (vf, cfr)
}

pub fn resolve_ilspy(app: &AppHandle) -> PathBuf {
    let rel = "resources/ilspycmd";
    let dir = if let Ok(p) = app.path().resolve(rel, tauri::path::BaseDirectory::Resource) {
        if p.join("ilspycmd.dll").exists() {
            p
        } else {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/ilspycmd")
        }
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/ilspycmd")
    };
    strip_verbatim(dir)
}

fn strip_verbatim(p: PathBuf) -> PathBuf {
    if !cfg!(windows) {
        return p;
    }
    match p.to_str() {
        Some(s) => {
            if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
                PathBuf::from(format!(r"\\{rest}"))
            } else if let Some(rest) = s.strip_prefix(r"\\?\") {
                PathBuf::from(rest)
            } else {
                p
            }
        }
        None => p,
    }
}

fn find_jar(app: &AppHandle, name: &str) -> PathBuf {
    let rel = format!("resources/{name}");

    if let Ok(p) = app
        .path()
        .resolve(&rel, tauri::path::BaseDirectory::Resource)
    {
        if p.exists() {
            return p;
        }
    }

    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join(name),
    ];
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("resources").join(name));
        candidates.push(cwd.join("src-tauri").join("resources").join(name));
    }
    for c in candidates {
        if c.exists() {
            return c;
        }
    }

    app.path()
        .resolve(&rel, tauri::path::BaseDirectory::Resource)
        .unwrap_or_else(|_| PathBuf::from(rel))
}
