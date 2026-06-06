
use endecompiler_lib::{archive, decompile, java};
use std::path::PathBuf;
use std::time::Duration;

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn single_class_decompiles() {
    let sample = match std::env::var("ENDEC_TEST_JAR") {
        Ok(p) => PathBuf::from(p),
        Err(_) => manifest().join("../samples/evilmod.jar"),
    };
    if !sample.exists() {
        eprintln!("skip: jar not found at {}", sample.display());
        return;
    }
    println!("jar = {}", sample.display());
    let info = java::detect();
    if !info.usable {
        eprintln!("skip: no usable java");
        return;
    }
    let opened = archive::open(&sample).expect("open");
    println!("classes ({}): {:?}", opened.classes.len(),
        opened.classes.iter().map(|c| &c.internal_name).take(8).collect::<Vec<_>>());
    let target = opened
        .classes
        .iter()
        .find(|c| !c.inner)
        .expect("at least one class")
        .internal_name
        .clone();
    println!("classes_root = {}", opened.classes_root.display());
    println!("target = {target}");

    let vf = manifest().join("resources/vineflower.jar");
    let cfr = manifest().join("resources/cfr.jar");

    let vfr = decompile::vineflower_single(
        &info.java_path,
        &vf,
        &opened.classes_root,
        &target,
        Duration::from_secs(60),
    );
    match &vfr {
        Ok(src) => println!("VINEFLOWER OK ({} bytes)\n{}", src.len(), &src[..src.len().min(200)]),
        Err(e) => println!("VINEFLOWER ERR: {e}"),
    }

    let cfrr = decompile::cfr_single(
        &info.java_path,
        &cfr,
        &opened.classes_root,
        &target,
        Duration::from_secs(60),
    );
    match &cfrr {
        Ok(src) => println!("CFR OK ({} bytes)\n{}", src.len(), &src[..src.len().min(200)]),
        Err(e) => println!("CFR ERR: {e}"),
    }

    assert!(vfr.is_ok() || cfrr.is_ok(), "at least one single-class decompiler must work");
}
