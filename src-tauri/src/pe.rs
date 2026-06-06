
use crate::analysis;
use crate::model::{DllReport, Finding, PeImport, PeSection, Severity, StringEntry};
use anyhow::{anyhow, Context, Result};
use goblin::pe::PE;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub fn detect_dotnet() -> Option<PathBuf> {
    let exe = if cfg!(windows) { "dotnet.exe" } else { "dotnet" };
    if let Ok(p) = which::which("dotnet") {
        return Some(p);
    }
    if let Ok(root) = std::env::var("DOTNET_ROOT") {
        let p = Path::new(&root).join(exe);
        if p.exists() {
            return Some(p);
        }
    }
    for c in [
        r"C:\Program Files\dotnet\dotnet.exe",
        r"C:\Program Files (x86)\dotnet\dotnet.exe",
        "/usr/local/share/dotnet/dotnet",
        "/usr/bin/dotnet",
        "/usr/lib/dotnet/dotnet",
        "/opt/homebrew/bin/dotnet",
    ] {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

pub fn decompile_dotnet(
    dotnet: &Path,
    ilspy_dir: &Path,
    assembly: &Path,
    timeout: Duration,
) -> Result<String> {
    let dll = ilspy_dir.join("ilspycmd.dll");
    if !dll.exists() {
        return Err(anyhow!("bundled ilspycmd not found at {}", dll.display()));
    }
    let mut cmd = Command::new(dotnet);
    cmd.arg(&dll)
        .arg(assembly)
        .env("DOTNET_ROLL_FORWARD", "LatestMajor")
        .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
        .env("DOTNET_NOLOGO", "1");
    let res = crate::decompile::run_with_timeout(cmd, timeout)?;
    if res.timed_out {
        return Err(anyhow!("ilspycmd timed out"));
    }
    if res.stdout.trim().is_empty() {
        return Err(anyhow!(
            "ilspycmd produced no output: {}",
            res.stderr.lines().next().unwrap_or("")
        ));
    }
    let mut out = res.stdout;
    if out.len() > 8_000_000 {
        out.truncate(8_000_000);
        out.push_str("\n// … output truncated …\n");
    }
    Ok(out)
}

const SCN_CODE: u32 = 0x0000_0020;
const SCN_EXEC: u32 = 0x2000_0000;
const SCN_READ: u32 = 0x4000_0000;
const SCN_WRITE: u32 = 0x8000_0000;

const DANGER: &[&str] = &[
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "NtCreateThreadEx",
    "QueueUserAPC", "SetThreadContext", "NtMapViewOfSection", "NtUnmapViewOfSection",
    "SetWindowsHookEx", "GetAsyncKeyState", "URLDownloadToFile", "WinHttpOpen",
    "InternetOpen", "ShellExecute", "WinExec", "CreateProcess", "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "AdjustTokenPrivileges",
    "OpenProcessToken", "GetProcAddress", "LoadLibrary", "CryptEncrypt", "CryptDecrypt",
    "CreateService", "OpenSCManager", "BitBlt", "VirtualProtect", "RtlCreateUserThread",
];

fn is_dangerous(name: &str) -> bool {
    DANGER.iter().any(|d| name.contains(d))
}

pub fn analyze_path(path: &Path) -> Result<DllReport> {
    let bytes = std::fs::read(path).context("reading PE file")?;
    let pe = PE::parse(&bytes).context("not a valid PE file")?;

    let machine = pe.header.coff_header.machine;
    let arch = match machine {
        0x014c => "x86",
        0x8664 => "x64",
        0xaa64 => "ARM64",
        0x01c0 | 0x01c4 => "ARM",
        _ => "unknown",
    }
    .to_string();

    let opt = pe.header.optional_header;
    let subsystem = opt
        .map(|o| match o.windows_fields.subsystem {
            1 => "Native",
            2 => "Windows GUI",
            3 => "Windows Console",
            9 => "Windows CE GUI",
            _ => "Other",
        })
        .unwrap_or("unknown")
        .to_string();
    let image_size = opt.map(|o| o.windows_fields.size_of_image as u64).unwrap_or(0);
    let entry_point = opt
        .map(|o| o.standard_fields.address_of_entry_point as u64)
        .unwrap_or(0);
    let is_dotnet = opt
        .map(|o| {
            o.data_directories
                .get_clr_runtime_header()
                .map(|d| d.size > 0)
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let signed = opt
        .map(|o| {
            o.data_directories
                .get_certificate_table()
                .map(|d| d.size > 0)
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let timestamp = fmt_timestamp(pe.header.coff_header.time_date_stamp);

    let mut sections = Vec::new();
    for s in &pe.sections {
        let name = s.name().unwrap_or("?").trim_end_matches('\0').to_string();
        let start = s.pointer_to_raw_data as usize;
        let end = (start + s.size_of_raw_data as usize).min(bytes.len());
        let ent = if start < end {
            analysis::entropy_bytes(&bytes[start..end])
        } else {
            0.0
        };
        let c = s.characteristics;
        let perms = format!(
            "{}{}{}",
            if c & SCN_READ != 0 { "R" } else { "-" },
            if c & SCN_WRITE != 0 { "W" } else { "-" },
            if c & SCN_EXEC != 0 { "X" } else { "-" },
        );
        let is_code = c & (SCN_CODE | SCN_EXEC) != 0;
        let wx = c & SCN_WRITE != 0 && c & SCN_EXEC != 0;
        let suspicious = wx || (is_code && ent > 7.0) || ent > 7.2;
        sections.push(PeSection {
            name,
            virtual_size: s.virtual_size as u64,
            raw_size: s.size_of_raw_data as u64,
            entropy: (ent * 100.0).round() / 100.0,
            perms,
            suspicious,
        });
    }

    let mut imp_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for imp in &pe.imports {
        imp_map
            .entry(imp.dll.to_string())
            .or_default()
            .push(imp.name.to_string());
    }
    let imports: Vec<PeImport> = imp_map
        .into_iter()
        .map(|(dll, mut functions)| {
            functions.sort();
            functions.dedup();
            let flagged = functions.iter().filter(|f| is_dangerous(f)).count();
            PeImport { dll, functions, flagged }
        })
        .collect();
    let import_count: usize = imports.iter().map(|i| i.functions.len()).sum();

    let mut exports: Vec<String> = pe
        .exports
        .iter()
        .filter_map(|e| e.name.map(|n| n.to_string()))
        .collect();
    exports.sort();
    let export_count = exports.len();

    let strings = extract_strings(&bytes);
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "binary".into());

    let mut import_blob = String::new();
    for imp in &imports {
        import_blob.push_str(&imp.dll);
        import_blob.push('\n');
        for f in &imp.functions {
            import_blob.push_str(f);
            import_blob.push('\n');
        }
    }
    let mut string_blob = String::with_capacity(64 * 1024);
    for s in &strings {
        string_blob.push_str(&s.value);
        string_blob.push('\n');
    }

    let mut findings = analysis::scan_text(&name, &import_blob);
    let mut string_findings = analysis::scan_text(&name, &string_blob);
    string_findings.retain(|f| !f.id.starts_with("pe-")); // imports-only signal
    findings.extend(string_findings);
    for sec in &sections {
        if sec.perms.contains('W') && sec.perms.contains('X') {
            findings.push(Finding {
                id: "pe-wx-section".into(),
                severity: Severity::High,
                category: "Native / Persistence".into(),
                class: name.clone(),
                line: 0,
                snippet: format!("{} is {}", sec.name, sec.perms),
                why: "A section is writable AND executable — self-modifying / unpacking code.".into(),
            });
        } else if sec.suspicious && sec.entropy > 7.0 {
            findings.push(Finding {
                id: "pe-packed-section".into(),
                severity: Severity::Medium,
                category: "Reflection / Obfuscation".into(),
                class: name.clone(),
                line: 0,
                snippet: format!("{} entropy {:.2}", sec.name, sec.entropy),
                why: "High-entropy section — the binary is likely packed/encrypted (hidden code).".into(),
            });
        }
    }
    if import_count == 0 {
        findings.push(Finding {
            id: "pe-no-imports".into(),
            severity: Severity::Medium,
            category: "Reflection / Obfuscation".into(),
            class: name.clone(),
            line: 0,
            snippet: "import table empty".into(),
            why: "No static imports — typical of a packed binary that resolves APIs at runtime.".into(),
        });
    }
    if is_dotnet {
        findings.push(Finding {
            id: "pe-dotnet".into(),
            severity: Severity::Info,
            category: "Reflection / Obfuscation".into(),
            class: name.clone(),
            line: 0,
            snippet: ".NET / CLR assembly".into(),
            why: "Managed .NET assembly — its IL can be inspected with a .NET decompiler for full source.".into(),
        });
    }
    if signed {
        findings.push(Finding {
            id: "pe-signed".into(),
            severity: Severity::Info,
            category: "Native / Persistence".into(),
            class: name.clone(),
            line: 0,
            snippet: "Authenticode signature present".into(),
            why: "The binary is digitally signed — verify the publisher, but signed binaries are far more likely legitimate.".into(),
        });
    }

    let mut analysis = analysis::finalize(findings, 1);
    if signed {
        let critical = analysis
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        if critical == 0 && matches!(analysis.verdict.level.as_str(), "malicious" | "likely_malicious") {
            analysis.verdict.level = "suspicious".into();
            analysis.verdict.label = "Suspicious (signed)".into();
            analysis.verdict.reasoning = format!(
                "{} Note: digitally signed — likely a legitimate program with sensitive capabilities (verify the publisher).",
                analysis.verdict.reasoning
            );
        }
    }

    Ok(DllReport {
        name,
        path: path.to_string_lossy().into_owned(),
        kind: if pe.is_lib { "DLL".into() } else { "EXE".into() },
        arch,
        subsystem,
        is_dotnet,
        signed,
        timestamp,
        image_size,
        entry_point,
        section_count: sections.len(),
        import_count,
        export_count,
        sections,
        imports,
        exports,
        string_count: strings.len(),
        analysis,
    })
}

pub fn strings_of(path: &Path) -> Result<Vec<StringEntry>> {
    let bytes = std::fs::read(path).context("reading PE file")?;
    Ok(extract_strings(&bytes))
}

fn push_string(out: &mut Vec<StringEntry>, seen: &mut std::collections::HashSet<String>, s: &str) {
    let t = s.trim();
    if t.len() < 5 || t.len() > 4000 {
        return;
    }
    if seen.insert(t.to_string()) {
        out.push(StringEntry {
            tag: tag_string(t).into(),
            value: t.to_string(),
            class: String::new(),
        });
    }
}

fn extract_strings(bytes: &[u8]) -> Vec<StringEntry> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    const CAP: usize = 60_000;

    let mut cur = String::new();
    for &b in bytes {
        if (0x20..0x7f).contains(&b) {
            cur.push(b as char);
        } else {
            push_string(&mut out, &mut seen, &cur);
            cur.clear();
        }
        if out.len() > CAP {
            return out;
        }
    }
    push_string(&mut out, &mut seen, &cur);

    let mut cur = String::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let c = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if (0x20..0x7f).contains(&c) {
            cur.push(c as u8 as char);
        } else {
            push_string(&mut out, &mut seen, &cur);
            cur.clear();
        }
        i += 2;
        if out.len() > CAP {
            break;
        }
    }
    push_string(&mut out, &mut seen, &cur);
    out
}

fn tag_string(s: &str) -> &'static str {
    let lower = s.to_ascii_lowercase();
    if lower.contains("http://") || lower.contains("https://") || lower.contains("ftp://") {
        return "url";
    }
    let parts: Vec<&str> = s.trim().split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        return "ip";
    }
    if lower.contains('\\')
        || lower.contains("appdata")
        || lower.contains(".dll")
        || lower.contains(".exe")
        || lower.contains("system32")
    {
        return "path";
    }
    if s.len() >= 80
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return "base64";
    }
    "plain"
}

pub fn disassemble(path: &Path) -> Result<String> {
    use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};

    let bytes = std::fs::read(path).context("reading PE file")?;
    let pe = PE::parse(&bytes).context("not a valid PE")?;
    let bitness = match pe.header.coff_header.machine {
        0x8664 | 0xaa64 => 64u32,
        _ => 32u32,
    };
    let image_base = pe
        .header
        .optional_header
        .map(|o| o.windows_fields.image_base)
        .unwrap_or(0);

    let mut out = String::new();
    let mut formatter = NasmFormatter::new();
    let mut total = 0usize;
    const CAP: usize = 40_000;

    for s in &pe.sections {
        if s.characteristics & SCN_EXEC == 0 {
            continue;
        }
        let name = s.name().unwrap_or("?").trim_end_matches('\0').to_string();
        let start = s.pointer_to_raw_data as usize;
        let end = (start + s.size_of_raw_data as usize).min(bytes.len());
        if start >= end {
            continue;
        }
        let code = &bytes[start..end];
        let rip = image_base + s.virtual_address as u64;
        out.push_str(&format!(
            "; ===== section {name}  ({} bytes @ {:#X}) =====\n",
            code.len(),
            rip
        ));
        let mut decoder = Decoder::with_ip(bitness, code, rip, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        let mut line = String::new();
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            line.clear();
            formatter.format(&instr, &mut line);
            let start_idx = (instr.ip() - rip) as usize;
            let len = instr.len();
            let raw: String = code[start_idx..(start_idx + len).min(code.len())]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join("");
            out.push_str(&format!("{:016X}  {:<20}  {}\n", instr.ip(), raw, line));
            total += 1;
            if total >= CAP {
                out.push_str("\n; … output capped …\n");
                return Ok(out);
            }
        }
        out.push('\n');
    }
    if out.is_empty() {
        return Err(anyhow!("no executable sections to disassemble"));
    }
    Ok(out)
}

fn fmt_timestamp(ts: u32) -> String {
    if ts == 0 || ts == 0xFFFF_FFFF {
        return String::new();
    }
    let days = (ts / 86400) as i64;
    let secs = (ts % 86400) as i64;
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y,
        m,
        d,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}
