
use crate::model::{ClassEntry, ResourceEntry, StringEntry};
use anyhow::{anyhow, Context, Result};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub struct OpenedArchive {
    pub _temp: TempDir,
    pub classes_root: PathBuf,
    pub classes: Vec<ClassEntry>,
    pub resources: Vec<ResourceEntry>,
    pub total_size: u64,
    pub original: PathBuf,
    pub name: String,
}

const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;

pub fn open(path: &Path) -> Result<OpenedArchive> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let temp = tempfile::Builder::new()
        .prefix("endecompiler-")
        .tempdir()
        .context("creating temp dir")?;
    let root = temp.path().to_path_buf();

    let (classes, resources, total_size) = if ext == "class" {
        open_single_class(path, &root)?
    } else {
        open_zip(path, &root)?
    };

    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive".into());

    Ok(OpenedArchive {
        _temp: temp,
        classes_root: root,
        classes,
        resources,
        total_size,
        original: path.to_path_buf(),
        name,
    })
}

fn open_single_class(
    path: &Path,
    root: &Path,
) -> Result<(Vec<ClassEntry>, Vec<ResourceEntry>, u64)> {
    let bytes = fs::read(path).context("reading .class file")?;
    let internal = this_class_name(&bytes)
        .unwrap_or_else(|| path.file_stem().unwrap().to_string_lossy().into_owned());
    let dest = root.join(format!("{internal}.class"));
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&dest, &bytes)?;
    let size = bytes.len() as u64;
    let classes = vec![ClassEntry {
        inner: internal.contains('$'),
        internal_name: internal,
        size,
    }];
    Ok((classes, Vec::new(), size))
}

fn open_zip(
    path: &Path,
    root: &Path,
) -> Result<(Vec<ClassEntry>, Vec<ResourceEntry>, u64)> {
    let file = fs::File::open(path).context("opening archive")?;
    let mut zip = zip::ZipArchive::new(file).context("reading zip; file may be corrupt")?;

    let mut classes = Vec::new();
    let mut resources = Vec::new();
    let mut total_size = 0u64;

    for i in 0..zip.len() {
        let mut entry = match zip.by_index(i) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        if name.contains("..") || name.starts_with('/') || name.starts_with('\\') {
            continue;
        }
        let size = entry.size();
        if size > MAX_ENTRY_BYTES {
            continue;
        }
        total_size += size;

        let safe_rel = sanitize_rel(&name);
        let dest = root.join(&safe_rel);
        if let Some(parent) = dest.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut buf = Vec::with_capacity(size as usize);
        if entry.read_to_end(&mut buf).is_err() {
            continue;
        }
        if fs::write(&dest, &buf).is_err() {
            continue;
        }

        if name.ends_with(".class") {
            let internal = name.trim_end_matches(".class").to_string();
            classes.push(ClassEntry {
                inner: internal.contains('$'),
                internal_name: internal,
                size,
            });
        } else {
            resources.push(ResourceEntry {
                kind: classify_resource(&name),
                path: name,
                size,
            });
        }
    }

    classes.sort_by(|a, b| a.internal_name.cmp(&b.internal_name));
    resources.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((classes, resources, total_size))
}

fn sanitize_rel(name: &str) -> PathBuf {
    let mut p = PathBuf::new();
    for comp in name.split(['/', '\\']) {
        if comp.is_empty() || comp == "." || comp == ".." {
            continue;
        }
        p.push(comp);
    }
    p
}

fn classify_resource(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    if base == "manifest.mf" {
        return "manifest".into();
    }
    if base == "fabric.mod.json"
        || base == "quilt.mod.json"
        || base == "mods.toml"
        || base == "neoforge.mods.toml"
        || base == "plugin.yml"
        || base == "bukkit.yml"
        || base == "paper-plugin.yml"
    {
        return "descriptor".into();
    }
    if lower.ends_with(".json") || lower.ends_with(".toml") || lower.ends_with(".yml") || lower.ends_with(".yaml") || lower.ends_with(".cfg") || lower.ends_with(".properties") {
        return "config".into();
    }
    if lower.ends_with(".png") || lower.ends_with(".jpg") || lower.ends_with(".gif") || lower.ends_with(".ogg") || lower.ends_with(".wav") {
        return "asset".into();
    }
    if lower.contains("mixins") && lower.ends_with(".json") {
        return "descriptor".into();
    }
    "other".into()
}

pub fn read_class_bytes(root: &Path, internal_name: &str) -> Result<Vec<u8>> {
    let path = root.join(format!("{internal_name}.class"));
    fs::read(&path).with_context(|| format!("reading {}", path.display()))
}

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cursor { b, pos: 0 }
    }
    fn u1(&mut self) -> Result<u8> {
        let v = *self.b.get(self.pos).ok_or_else(|| anyhow!("eof"))?;
        self.pos += 1;
        Ok(v)
    }
    fn u2(&mut self) -> Result<u16> {
        let hi = self.u1()? as u16;
        let lo = self.u1()? as u16;
        Ok((hi << 8) | lo)
    }
    fn skip(&mut self, n: usize) -> Result<()> {
        if self.pos + n > self.b.len() {
            return Err(anyhow!("eof"));
        }
        self.pos += n;
        Ok(())
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.b.len() {
            return Err(anyhow!("eof"));
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

enum Const {
    Utf8(String),
    StringRef(u16),
    ClassRef(u16),
    Other,
}

fn parse_pool(bytes: &[u8]) -> Result<Vec<Const>> {
    let mut c = Cursor::new(bytes);
    let magic = (c.u2()? as u32) << 16 | c.u2()? as u32;
    if magic != 0xCAFEBABE {
        return Err(anyhow!("not a class file"));
    }
    let _minor = c.u2()?;
    let _major = c.u2()?;
    let count = c.u2()?;
    let mut pool: Vec<Const> = Vec::with_capacity(count as usize);
    pool.push(Const::Other);
    let mut i = 1u16;
    while i < count {
        let tag = c.u1()?;
        match tag {
            1 => {
                let len = c.u2()? as usize;
                let raw = c.bytes(len)?;
                pool.push(Const::Utf8(String::from_utf8_lossy(raw).into_owned()));
            }
            7 => {
                pool.push(Const::ClassRef(c.u2()?));
            }
            8 => {
                pool.push(Const::StringRef(c.u2()?));
            }
            3 | 4 => {
                c.skip(4)?;
                pool.push(Const::Other);
            }
            5 | 6 => {
                c.skip(8)?;
                pool.push(Const::Other);
                pool.push(Const::Other);
                i += 1;
            }
            9 | 10 | 11 | 12 | 17 | 18 => {
                c.skip(4)?;
                pool.push(Const::Other);
            }
            15 => {
                c.skip(3)?;
                pool.push(Const::Other);
            }
            16 | 19 | 20 => {
                c.skip(2)?;
                pool.push(Const::Other);
            }
            _ => return Err(anyhow!("unknown constant tag {tag}")),
        }
        i += 1;
    }
    Ok(pool)
}

fn this_class_name(bytes: &[u8]) -> Option<String> {
    let pool = parse_pool(bytes).ok()?;
    let mut c = Cursor::new(bytes);
    c.skip(8).ok()?;
    let count = c.u2().ok()?;
    let mut i = 1u16;
    while i < count {
        let tag = c.u1().ok()?;
        match tag {
            1 => {
                let len = c.u2().ok()? as usize;
                c.skip(len).ok()?;
            }
            7 | 8 | 16 | 19 | 20 => {
                c.skip(2).ok()?;
            }
            15 => {
                c.skip(3).ok()?;
            }
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => {
                c.skip(4).ok()?;
            }
            5 | 6 => {
                c.skip(8).ok()?;
                i += 1;
            }
            _ => return None,
        }
        i += 1;
    }
    let _access = c.u2().ok()?;
    let this_class = c.u2().ok()?;
    match pool.get(this_class as usize)? {
        Const::ClassRef(name_idx) => match pool.get(*name_idx as usize)? {
            Const::Utf8(s) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

pub fn extract_strings(root: &Path, classes: &[ClassEntry]) -> Vec<StringEntry> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for class in classes {
        let Ok(bytes) = read_class_bytes(root, &class.internal_name) else {
            continue;
        };
        let Ok(pool) = parse_pool(&bytes) else {
            continue;
        };
        let mut literal_idx = std::collections::HashSet::new();
        for c in &pool {
            if let Const::StringRef(idx) = c {
                literal_idx.insert(*idx);
            }
        }
        for (i, c) in pool.iter().enumerate() {
            if let Const::Utf8(s) = c {
                let is_literal = literal_idx.contains(&(i as u16));
                let tag = tag_string(s);
                if is_literal || tag != "plain" {
                    if s.trim().is_empty() || s.len() > 4000 {
                        continue;
                    }
                    let key = (class.internal_name.clone(), s.clone());
                    if seen.insert(key) {
                        out.push(StringEntry {
                            value: s.clone(),
                            class: class.internal_name.clone(),
                            tag: tag.to_string(),
                        });
                    }
                }
            }
        }
    }
    out
}

pub fn extract_symbols(root: &Path, internal_name: &str) -> String {
    let Ok(bytes) = read_class_bytes(root, internal_name) else {
        return String::new();
    };
    let Ok(pool) = parse_pool(&bytes) else {
        return String::new();
    };
    let mut out = String::with_capacity(2048);
    for c in &pool {
        if let Const::Utf8(s) = c {
            out.push_str(s);
            out.push('\n');
        }
    }
    out
}

fn tag_string(s: &str) -> &'static str {
    let lower = s.to_ascii_lowercase();
    if lower.contains("http://") || lower.contains("https://") || lower.contains("ftp://") {
        return "url";
    }
    if is_ipish(s) {
        return "ip";
    }
    if looks_like_path(&lower) {
        return "path";
    }
    if looks_base64(s) {
        return "base64";
    }
    "plain"
}

fn is_ipish(s: &str) -> bool {
    let t = s.trim();
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn looks_like_path(lower: &str) -> bool {
    lower.contains("appdata")
        || lower.contains(".minecraft")
        || lower.contains("\\users\\")
        || lower.contains("/users/")
        || lower.contains("local storage")
        || lower.contains("leveldb")
        || lower.contains("login data")
        || lower.contains("\\discord")
        || lower.contains("/discord")
        || lower.contains(".ssh")
        || lower.contains("cookies")
        || lower.contains("system32")
}

fn looks_base64(s: &str) -> bool {
    if s.len() < 80 {
        return false;
    }
    let ok = s
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=');
    ok && s.chars().filter(|c| c.is_ascii_uppercase()).count() > 4
}
