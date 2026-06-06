
use endecompiler_lib::{analysis, archive, decompile, java, metadata};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn malicious_sample_is_flagged() {
    let sample = manifest().join("../samples/evilmod.jar");
    if !sample.exists() {
        eprintln!("skip: sample jar not built ({})", sample.display());
        return;
    }
    let info = java::detect();
    let opened = archive::open(&sample).expect("open jar");
    assert!(!opened.classes.is_empty(), "should enumerate classes");

    let strings = archive::extract_strings(&opened.classes_root, &opened.classes);
    assert!(
        strings.iter().any(|s| s.tag == "url"),
        "should capture URL string constants"
    );

    let md = metadata::parse(&opened.classes_root, &opened.resources);
    assert_eq!(md.loader, "fabric");
    assert_eq!(md.mod_id, "evilmod");

    let mut sources: HashMap<String, String> = HashMap::new();
    if info.usable {
        let vf = manifest().join("resources/vineflower.jar");
        let out = tempfile::tempdir().unwrap();
        decompile::vineflower_all(
            &info.java_path,
            &vf,
            &opened.classes_root,
            out.path(),
            Duration::from_secs(120),
            |_| {},
        )
        .expect("vineflower batch");
        for (internal, code) in decompile::collect_sources(out.path()).unwrap() {
            sources.insert(internal, code);
        }
        assert!(
            sources.keys().any(|k| k.contains("TokenGrabber")),
            "decompiled source should include TokenGrabber, got: {:?}",
            sources.keys().collect::<Vec<_>>()
        );
    } else {
        eprintln!("note: no usable Java; analyzing on string constants only");
    }

    let class_names: Vec<String> = opened
        .classes
        .iter()
        .map(|c| c.internal_name.clone())
        .collect();
    let mut symbols: HashMap<String, String> = HashMap::new();
    for c in &opened.classes {
        let outer = c.internal_name.split('$').next().unwrap_or(&c.internal_name).to_string();
        symbols
            .entry(outer)
            .or_default()
            .push_str(&archive::extract_symbols(&opened.classes_root, &c.internal_name));
    }
    let report = analysis::analyze(&sources, &symbols, &[], &class_names);

    let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    println!("verdict: {} (score {})", report.verdict.label, report.verdict.score);
    println!("finding ids: {ids:?}");

    assert!(ids.contains(&"discord-webhook"), "must flag Discord webhook");
    assert!(ids.contains(&"raw-ip"), "must flag raw C2 IP");
    assert!(
        report.verdict.level == "malicious" || report.verdict.level == "likely_malicious",
        "verdict should be malicious-ish, was {}",
        report.verdict.level
    );

    assert!(ids.contains(&"process-exec"), "must flag process execution");
    assert!(ids.contains(&"robot-capture"), "must flag screen capture");
    assert!(ids.contains(&"browser-storage"), "must flag browser/Discord storage access");
    assert!(
        ids.contains(&"dynamic-code-loading"),
        "must escalate decode+reflection combo"
    );
}
