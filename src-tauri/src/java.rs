
use crate::model::JavaInfo;
use std::path::{Path, PathBuf};
use std::process::Command;

const MIN_MAJOR: u32 = 17;

fn candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let exe = if cfg!(windows) { "java.exe" } else { "java" };

    if let Ok(home) = std::env::var("JAVA_HOME") {
        if !home.is_empty() {
            out.push(Path::new(&home).join("bin").join(exe));
        }
    }

    let roots: &[&str] = if cfg!(windows) {
        &[
            r"C:\Program Files\Java",
            r"C:\Program Files\Eclipse Adoptium",
            r"C:\Program Files\Microsoft\jdk",
            r"C:\Program Files\Amazon Corretto",
            r"C:\Program Files\Zulu",
        ]
    } else if cfg!(target_os = "macos") {
        &[
            "/Library/Java/JavaVirtualMachines",
            "/opt/homebrew/opt/openjdk/bin",
            "/usr/local/opt/openjdk/bin",
        ]
    } else {
        &["/usr/lib/jvm", "/usr/local/lib/jvm"]
    };
    for root in roots {
        collect_from_root(Path::new(root), exe, &mut out);
    }

    if let Ok(p) = which::which("java") {
        out.push(p);
    }
    out
}

fn collect_from_root(root: &Path, exe: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut dirs: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    dirs.sort();
    dirs.reverse();
    for d in dirs {
        let direct = d.join("bin").join(exe);
        if direct.exists() {
            out.push(direct);
        }
        let mac = d.join("Contents").join("Home").join("bin").join(exe);
        if mac.exists() {
            out.push(mac);
        }
    }
}

fn parse_version(text: &str) -> Option<(String, u32)> {
    let start = text.find('"')?;
    let rest = &text[start + 1..];
    let end = rest.find('"')?;
    let full = rest[..end].to_string();
    let major = if let Some(stripped) = full.strip_prefix("1.") {
        stripped.split('.').next()?.parse().ok()?
    } else {
        full.split(['.', '+', '-']).next()?.parse().ok()?
    };
    Some((full, major))
}

fn probe(java: &Path) -> Option<(String, u32)> {
    let mut cmd = Command::new(java);
    cmd.arg("-version");
    crate::decompile::hide_window(&mut cmd);
    let out = cmd.output().ok()?;
    let text = if out.stderr.is_empty() {
        String::from_utf8_lossy(&out.stdout).into_owned()
    } else {
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    parse_version(&text)
}

pub fn detect() -> JavaInfo {
    let mut best: Option<(PathBuf, String, u32)> = None;
    for cand in candidates() {
        if !cand.exists() {
            continue;
        }
        if let Some((full, major)) = probe(&cand) {
            let better = match &best {
                Some((_, _, m)) => major > *m,
                None => true,
            };
            if better {
                best = Some((cand, full, major));
            }
        }
    }

    match best {
        Some((path, full, major)) => {
            let usable = major >= MIN_MAJOR;
            JavaInfo {
                found: true,
                version: full,
                major,
                java_path: path.to_string_lossy().into_owned(),
                usable,
                note: if usable {
                    format!("Java {major} detected at {}", path.display())
                } else {
                    format!(
                        "Java {major} is too old. End Decompiler needs Java {MIN_MAJOR}+."
                    )
                },
            }
        }
        None => JavaInfo {
            found: false,
            version: String::new(),
            major: 0,
            java_path: String::new(),
            usable: false,
            note: "No Java runtime found. Install a JRE/JDK 17+ (e.g. Adoptium Temurin) to enable decompilation.".into(),
        },
    }
}

pub fn javap_for(java_path: &str) -> PathBuf {
    let java = Path::new(java_path);
    let exe = if cfg!(windows) { "javap.exe" } else { "javap" };
    match java.parent() {
        Some(bin) => bin.join(exe),
        None => PathBuf::from(exe),
    }
}
