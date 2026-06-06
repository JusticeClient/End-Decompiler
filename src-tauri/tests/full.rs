
use endecompiler_lib::{analysis, archive, decompile, java, metadata};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn full_pipeline_report() {
    let jar = match std::env::var("ENDEC_TEST_JAR") {
        Ok(p) => PathBuf::from(p),
        Err(_) => manifest().join("../samples/evilmod.jar"),
    };
    if !jar.exists() {
        eprintln!("skip: jar not found at {}", jar.display());
        return;
    }
    println!("\n=== JAR: {} ===", jar.display());

    let info = java::detect();
    println!("java: usable={} version={} path={}", info.usable, info.version, info.java_path);

    let opened = archive::open(&jar).expect("open");
    println!("classes: {}  resources: {}", opened.classes.len(), opened.resources.len());
    println!("resources list: {:?}", opened.resources.iter().map(|r| (&r.path, &r.kind)).collect::<Vec<_>>());

    let t = Instant::now();
    let strings = archive::extract_strings(&opened.classes_root, &opened.classes);
    println!("\n[strings] count={} ({} ms)", strings.len(), t.elapsed().as_millis());
    for s in strings.iter().take(6) {
        println!("   [{}] {}", s.tag, &s.value[..s.value.len().min(80)]);
    }

    let md = metadata::parse(&opened.classes_root, &opened.resources);
    println!("\n[metadata] loader={:?} modId={:?} name={:?} version={:?}", md.loader, md.mod_id, md.mod_name, md.version);
    println!("   authors={:?} entrypoints={:?} mixins={:?}", md.authors, md.entrypoints, md.mixins);
    println!("   manifest entries={} rawDescriptors={}", md.manifest.len(), md.raw_descriptors.len());

    let mut sources: HashMap<String, String> = HashMap::new();
    if info.usable {
        let vf = manifest().join("resources/vineflower.jar");
        let out = tempfile::tempdir().unwrap();
        let t = Instant::now();
        let mut progress = 0;
        let res = decompile::vineflower_all(
            &info.java_path, &vf, &opened.classes_root, out.path(),
            Duration::from_secs(120), |_c| progress += 1,
        );
        match res {
            Ok(()) => {
                let collected = decompile::collect_sources(out.path()).unwrap();
                println!("\n[decompile_all] OK progress_events={} collected={} ({} ms)",
                    progress, collected.len(), t.elapsed().as_millis());
                for (k, _) in &collected { println!("   src: {k}"); }
                for (k, v) in collected { sources.insert(k, v); }
            }
            Err(e) => println!("\n[decompile_all] ERR: {e}"),
        }
    }

    let class_names: Vec<String> = opened.classes.iter().map(|c| c.internal_name.clone()).collect();
    let mut symbols: HashMap<String, String> = HashMap::new();
    for c in &opened.classes {
        let outer = c.internal_name.split('$').next().unwrap_or(&c.internal_name).to_string();
        symbols
            .entry(outer)
            .or_default()
            .push_str(&archive::extract_symbols(&opened.classes_root, &c.internal_name));
    }
    let res_heads: Vec<(String, Vec<u8>)> = opened
        .resources
        .iter()
        .filter_map(|r| {
            std::fs::read(opened.classes_root.join(&r.path))
                .ok()
                .map(|b| (r.path.clone(), b.into_iter().take(16).collect()))
        })
        .collect();
    let t = Instant::now();
    let report = analysis::analyze(&sources, &symbols, &res_heads, &class_names);
    println!("\n[analysis] verdict={} score={} findings={} ({} ms)",
        report.verdict.label, report.verdict.score, report.findings.len(), t.elapsed().as_millis());
    println!("   reasoning: {}", report.verdict.reasoning);
}
