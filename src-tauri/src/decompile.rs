
use anyhow::{anyhow, Context, Result};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[cfg(windows)]
pub fn hide_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}
#[cfg(not(windows))]
pub fn hide_window(_cmd: &mut Command) {}

pub struct ProcOutput {
    #[allow(dead_code)]
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

pub fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<ProcOutput> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    hide_window(&mut cmd);
    let mut child = cmd.spawn().context("spawning subprocess")?;

    let mut out_pipe = child.stdout.take().unwrap();
    let mut err_pipe = child.stderr.take().unwrap();
    let (otx, orx) = mpsc::channel();
    let (etx, erx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out_pipe.read_to_string(&mut s);
        let _ = otx.send(s);
    });
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = err_pipe.read_to_string(&mut s);
        let _ = etx.send(s);
    });

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let code = loop {
        match child.try_wait()? {
            Some(status) => break status.code().unwrap_or(-1),
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break -1;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    };

    let stdout = orx.recv().unwrap_or_default();
    let stderr = erx.recv().unwrap_or_default();
    Ok(ProcOutput {
        code,
        stdout,
        stderr,
        timed_out,
    })
}

fn class_and_inners(root: &Path, internal_name: &str) -> Vec<PathBuf> {
    let outer = internal_name.split('$').next().unwrap_or(internal_name);
    let mut paths = vec![root.join(format!("{outer}.class"))];
    let dir = root.join(outer).parent().map(|p| p.to_path_buf());
    if let Some(dir) = dir {
        let prefix = format!("{}$", outer.rsplit('/').next().unwrap_or(outer));
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with(&prefix) && name.ends_with(".class") {
                    paths.push(e.path());
                }
            }
        }
    }
    paths.into_iter().filter(|p| p.exists()).collect()
}

pub fn vineflower_single(
    java: &str,
    vineflower_jar: &Path,
    classes_root: &Path,
    internal_name: &str,
    timeout: Duration,
) -> Result<String> {
    let outer = internal_name.split('$').next().unwrap_or(internal_name);
    let out_dir = tempfile::tempdir().context("vineflower out dir")?;
    let inputs = class_and_inners(classes_root, internal_name);
    if inputs.is_empty() {
        return Err(anyhow!("class file not found on disk"));
    }

    let mut cmd = Command::new(java);
    cmd.arg("-jar")
        .arg(vineflower_jar)
        .arg("-dgs=1") // decompile generic signatures
        .args(inputs.iter())
        .arg(out_dir.path());
    let res = run_with_timeout(cmd, timeout)?;
    if res.timed_out {
        return Err(anyhow!("Vineflower timed out"));
    }

    let simple = outer.rsplit('/').next().unwrap_or(outer);
    let java_path = find_java_file(out_dir.path(), simple)?;
    let src = std::fs::read_to_string(&java_path)?;
    if src.trim().is_empty() {
        return Err(anyhow!("Vineflower produced empty output"));
    }
    if is_decompiler_stub(&src) {
        return Err(anyhow!("Vineflower could not decompile this class (internal error)"));
    }
    Ok(src)
}

pub fn is_decompiler_stub(src: &str) -> bool {
    let head: String = src.lines().take(40).collect::<Vec<_>>().join("\n");
    head.contains("$VF: Couldn't be decompiled")
        || head.contains("Please report this to the Vineflower")
        || head.contains("// $FF: Couldn't be decompiled")
        || (head.contains("Couldn't be decompiled") && head.contains("decompiler"))
}

fn find_java_file(dir: &Path, simple: &str) -> Result<PathBuf> {
    let want = format!("{simple}.java");
    let mut first: Option<PathBuf> = None;
    for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("java") {
            if p.file_name().and_then(|n| n.to_str()) == Some(&want) {
                return Ok(p.to_path_buf());
            }
            first.get_or_insert_with(|| p.to_path_buf());
        }
    }
    first.ok_or_else(|| anyhow!("no .java produced"))
}

pub fn cfr_single(
    java: &str,
    cfr_jar: &Path,
    classes_root: &Path,
    internal_name: &str,
    timeout: Duration,
) -> Result<String> {
    let class_file = classes_root.join(format!(
        "{}.class",
        internal_name.split('$').next().unwrap_or(internal_name)
    ));
    let mut cmd = Command::new(java);
    cmd.arg("-jar")
        .arg(cfr_jar)
        .arg(&class_file)
        .arg("--extraclasspath")
        .arg(classes_root)
        .arg("--silent")
        .arg("true")
        .arg("--comments")
        .arg("false");
    let res = run_with_timeout(cmd, timeout)?;
    if res.timed_out {
        return Err(anyhow!("CFR timed out"));
    }
    if res.stdout.trim().is_empty() {
        return Err(anyhow!(
            "CFR produced no output: {}",
            res.stderr.lines().next().unwrap_or("")
        ));
    }
    Ok(res.stdout)
}

pub fn javap(
    javap_path: &Path,
    classes_root: &Path,
    internal_name: &str,
    timeout: Duration,
) -> Result<String> {
    let fqcn = internal_name.replace('/', ".");
    let mut cmd = Command::new(javap_path);
    cmd.arg("-c")
        .arg("-p")
        .arg("-constants")
        .arg("-classpath")
        .arg(classes_root)
        .arg(&fqcn);
    let res = run_with_timeout(cmd, timeout)?;
    if res.timed_out {
        return Err(anyhow!("javap timed out"));
    }
    if res.stdout.trim().is_empty() {
        return Err(anyhow!(
            "javap failed: {}",
            res.stderr.lines().next().unwrap_or("")
        ));
    }
    Ok(res.stdout)
}

pub fn vineflower_all<F: FnMut(String)>(
    java: &str,
    vineflower_jar: &Path,
    classes_root: &Path,
    out_dir: &Path,
    timeout: Duration,
    mut on_progress: F,
) -> Result<()> {
    let mut cmd = Command::new(java);
    cmd.arg("-jar")
        .arg(vineflower_jar)
        .arg("-dgs=1")
        .arg(classes_root)
        .arg(out_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    hide_window(&mut cmd);
    let mut child = cmd.spawn().context("spawning Vineflower")?;

    let stderr = child.stderr.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    let tx2 = tx.clone();
    let h1 = std::thread::spawn(move || stream_lines(stderr, tx));
    let h2 = std::thread::spawn(move || stream_lines(stdout, tx2));

    let deadline = Instant::now() + timeout;
    loop {
        while let Ok(line) = rx.try_recv() {
            if let Some(name) = parse_progress(&line) {
                on_progress(name);
            }
        }
        match child.try_wait()? {
            Some(_) => break,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(anyhow!("Vineflower batch timed out"));
                }
                std::thread::sleep(Duration::from_millis(40));
            }
        }
    }
    let _ = h1.join();
    let _ = h2.join();
    while let Ok(line) = rx.try_recv() {
        if let Some(name) = parse_progress(&line) {
            on_progress(name);
        }
    }
    Ok(())
}

fn stream_lines<R: Read>(reader: R, tx: mpsc::Sender<String>) {
    let buf = BufReader::new(reader);
    for line in buf.lines().map_while(Result::ok) {
        if tx.send(line).is_err() {
            break;
        }
    }
}

fn parse_progress(line: &str) -> Option<String> {
    let idx = line.find("Decompiling class")?;
    let rest = line[idx + "Decompiling class".len()..].trim();
    let name = rest.split_whitespace().next()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.replace('.', "/"))
    }
}

pub fn collect_sources(dir: &Path) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut found_java = false;
    for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("java") {
            found_java = true;
            if let Ok(src) = std::fs::read_to_string(p) {
                if let Ok(rel) = p.strip_prefix(dir) {
                    let internal = rel
                        .to_string_lossy()
                        .trim_end_matches(".java")
                        .replace('\\', "/");
                    out.push((internal, src));
                }
            }
        }
    }
    if !found_java {
        for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("jar") {
                if let Ok(file) = std::fs::File::open(p) {
                    if let Ok(mut zip) = zip::ZipArchive::new(file) {
                        for i in 0..zip.len() {
                            if let Ok(mut e) = zip.by_index(i) {
                                let name = e.name().to_string();
                                if name.ends_with(".java") {
                                    let mut s = String::new();
                                    if e.read_to_string(&mut s).is_ok() {
                                        let internal =
                                            name.trim_end_matches(".java").replace('\\', "/");
                                        out.push((internal, s));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}
