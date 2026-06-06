
use endecompiler_lib::{archive, decompile, java};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn exports_source_zip() {
    let sample = manifest().join("../samples/evilmod.jar");
    if !sample.exists() {
        eprintln!("skip: sample jar not built");
        return;
    }
    let info = java::detect();
    if !info.usable {
        eprintln!("skip: no usable java");
        return;
    }
    let opened = archive::open(&sample).expect("open");
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
    .expect("decompile");
    let sources = decompile::collect_sources(out.path()).unwrap();
    assert!(!sources.is_empty());

    let zip_path = out.path().join("source.zip");
    {
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (internal, src) in &sources {
            zip.start_file(format!("{internal}.java"), opts).unwrap();
            zip.write_all(src.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
    }

    let f = std::fs::File::open(&zip_path).unwrap();
    let mut z = zip::ZipArchive::new(f).unwrap();
    let names: Vec<String> = (0..z.len())
        .map(|i| z.by_index(i).unwrap().name().to_string())
        .collect();
    assert!(
        names.iter().any(|n| n == "com/evil/TokenGrabber.java"),
        "zip should contain the source at its package path, got: {names:?}"
    );
    let mut body = String::new();
    z.by_name("com/evil/TokenGrabber.java")
        .unwrap()
        .read_to_string(&mut body)
        .unwrap();
    assert!(body.contains("class TokenGrabber"), "zip entry should be real source");
    println!("zip OK: {} entries, e.g. {:?}", names.len(), &names[..names.len().min(4)]);
}
