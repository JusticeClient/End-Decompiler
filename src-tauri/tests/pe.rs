
use endecompiler_lib::pe;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn decompiles_dotnet_to_csharp() {
    let Some(dotnet) = pe::detect_dotnet() else {
        eprintln!("skip: no dotnet runtime");
        return;
    };
    let ilspy = manifest().join("resources/ilspycmd");
    let target = ilspy.join("ICSharpCode.Decompiler.dll");
    if !ilspy.join("ilspycmd.dll").exists() || !target.exists() {
        eprintln!("skip: ilspycmd not bundled");
        return;
    }
    let report = pe::analyze_path(&target).expect("analyze");
    assert!(report.is_dotnet, "ICSharpCode.Decompiler.dll should be detected as .NET");

    let cs = pe::decompile_dotnet(&dotnet, &ilspy, &target, Duration::from_secs(120))
        .expect("dotnet decompile");
    println!("C# output: {} lines, first: {}", cs.lines().count(), cs.lines().next().unwrap_or(""));
    assert!(
        cs.contains("namespace") || cs.contains("class") || cs.contains("using "),
        "should produce readable C#"
    );
}

fn pick_dll() -> Option<String> {
    if let Ok(p) = std::env::var("ENDEC_TEST_PE") {
        if Path::new(&p).exists() {
            return Some(p);
        }
    }
    for c in [
        r"C:\Windows\System32\ws2_32.dll",
        r"C:\Windows\System32\winhttp.dll",
        r"C:\Windows\System32\kernel32.dll",
    ] {
        if Path::new(c).exists() {
            return Some(c.to_string());
        }
    }
    None
}

#[test]
fn analyzes_real_dll() {
    let Some(dll) = pick_dll() else {
        eprintln!("skip: no system DLL found");
        return;
    };
    let path = Path::new(&dll);
    let report = pe::analyze_path(path).expect("analyze dll");

    println!(
        "{} | {} {} | subsystem={} | dotnet={} | built {}",
        report.name, report.kind, report.arch, report.subsystem, report.is_dotnet, report.timestamp
    );
    println!(
        "sections={} imports={} exports={} strings={}",
        report.section_count, report.import_count, report.export_count, report.string_count
    );
    println!("verdict: {} ({})", report.analysis.verdict.label, report.analysis.verdict.score);
    for f in &report.analysis.findings {
        println!("  [{}] {} :: {} :: {}", f.severity.as_str(), f.id, f.class, f.snippet);
    }
    for sec in &report.sections {
        println!("  section {:8} {} entropy={:.2} {}", sec.name, sec.perms, sec.entropy,
            if sec.suspicious { "SUSPICIOUS" } else { "" });
    }

    println!("signed={}", report.signed);
    assert!(report.section_count > 0, "should parse sections");
    assert!(
        report.analysis.verdict.level == "clean" || report.analysis.verdict.level == "suspicious",
        "legit signed binary should not be malicious, got {}",
        report.analysis.verdict.label
    );
    assert!(report.string_count > 0, "should extract strings");

    let asm = pe::disassemble(path).expect("disassemble");
    println!("disasm first lines:\n{}", asm.lines().take(8).collect::<Vec<_>>().join("\n"));
    assert!(asm.lines().count() > 20, "should disassemble many instructions");
}
