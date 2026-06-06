
use crate::model::{Metadata, ResourceEntry};
use std::fs;
use std::path::Path;

pub fn parse(root: &Path, resources: &[ResourceEntry]) -> Metadata {
    let mut md = Metadata::default();

    for res in resources {
        let lower = res.path.to_ascii_lowercase();
        let base = lower.rsplit('/').next().unwrap_or(&lower);
        let Ok(content) = fs::read_to_string(root.join(&res.path)) else {
            continue;
        };

        match base {
            "manifest.mf" => parse_manifest(&content, &mut md),
            "fabric.mod.json" | "quilt.mod.json" => {
                parse_fabric(&content, &mut md);
                md.raw_descriptors.push((res.path.clone(), pretty_json(&content)));
            }
            "mods.toml" | "neoforge.mods.toml" => {
                parse_forge(&content, &mut md);
                md.raw_descriptors.push((res.path.clone(), content));
            }
            "plugin.yml" | "bukkit.yml" | "paper-plugin.yml" => {
                parse_bukkit(&content, &mut md);
                md.raw_descriptors.push((res.path.clone(), content));
            }
            _ => {}
        }
    }

    dedup(&mut md.authors);
    dedup(&mut md.dependencies);
    dedup(&mut md.entrypoints);
    dedup(&mut md.mixins);
    md
}

fn dedup(v: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    v.retain(|x| !x.trim().is_empty() && seen.insert(x.clone()));
}

fn parse_manifest(content: &str, md: &mut Metadata) {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for raw in content.lines() {
        let line = raw.trim_end_matches('\r');
        if line.starts_with(' ') {
            if let Some(last) = pairs.last_mut() {
                last.1.push_str(line.trim_start());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            pairs.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    for (k, v) in &pairs {
        match k.as_str() {
            "Implementation-Title" if md.mod_name.is_empty() => md.mod_name = v.clone(),
            "Implementation-Version" if md.version.is_empty() => md.version = v.clone(),
            "Specification-Vendor" | "Implementation-Vendor" => md.authors.push(v.clone()),
            _ => {}
        }
    }
    md.manifest = pairs;
}

fn parse_fabric(content: &str, md: &mut Metadata) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(content) else {
        return;
    };
    md.loader = if content.contains("quilt_loader") || v.get("quilt_loader").is_some() {
        "quilt".into()
    } else {
        "fabric".into()
    };
    let obj = v.get("quilt_loader").unwrap_or(&v);
    set_if(&mut md.mod_id, str_of(obj.get("id")));
    set_if(&mut md.mod_name, str_of(v.get("name")));
    set_if(&mut md.version, str_of(obj.get("version")));
    set_if(&mut md.description, str_of(v.get("description")));

    if let Some(arr) = v.get("authors").and_then(|a| a.as_array()) {
        for a in arr {
            if let Some(s) = a.as_str() {
                md.authors.push(s.to_string());
            } else if let Some(s) = a.get("name").and_then(|n| n.as_str()) {
                md.authors.push(s.to_string());
            }
        }
    }
    if let Some(ep) = v.get("entrypoints").and_then(|e| e.as_object()) {
        for (kind, val) in ep {
            collect_entrypoints(kind, val, md);
        }
    }
    if let Some(mix) = v.get("mixins") {
        collect_mixins(mix, md);
    }
    if let Some(dep) = v.get("depends").and_then(|d| d.as_object()) {
        for (k, val) in dep {
            md.dependencies.push(format!("{k} {}", val.as_str().unwrap_or("")));
        }
    }
}

fn collect_entrypoints(kind: &str, val: &serde_json::Value, md: &mut Metadata) {
    if let Some(arr) = val.as_array() {
        for e in arr {
            let target = e
                .as_str()
                .map(|s| s.to_string())
                .or_else(|| e.get("value").and_then(|v| v.as_str()).map(|s| s.to_string()))
                .unwrap_or_default();
            if !target.is_empty() {
                md.entrypoints.push(format!("{kind}: {target}"));
            }
        }
    }
}

fn collect_mixins(val: &serde_json::Value, md: &mut Metadata) {
    match val {
        serde_json::Value::String(s) => md.mixins.push(s.clone()),
        serde_json::Value::Array(arr) => {
            for m in arr {
                if let Some(s) = m.as_str() {
                    md.mixins.push(s.to_string());
                } else if let Some(s) = m.get("config").and_then(|c| c.as_str()) {
                    md.mixins.push(s.to_string());
                }
            }
        }
        _ => {}
    }
}

fn parse_forge(content: &str, md: &mut Metadata) {
    md.loader = if content.contains("neoforge") {
        "neoforge".into()
    } else {
        "forge".into()
    };
    set_if(&mut md.mod_id, toml_first(content, "modId"));
    set_if(&mut md.mod_name, toml_first(content, "displayName"));
    set_if(&mut md.version, toml_first(content, "version"));
    set_if(&mut md.description, toml_first(content, "description"));
    if let Some(a) = toml_first(content, "authors") {
        md.authors.push(a);
    }
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with("modId") {
            if let Some(v) = toml_value(t) {
                md.dependencies.push(v);
            }
        }
    }
}

fn parse_bukkit(content: &str, md: &mut Metadata) {
    if md.loader.is_empty() {
        md.loader = "bukkit/spigot".into();
    }
    for raw in content.lines() {
        let line = raw.trim_end_matches('\r');
        if line.starts_with(' ') || line.starts_with('-') {
            let item = line.trim_start_matches([' ', '-']).trim();
            if !item.is_empty() && item.contains(|c: char| c.is_alphanumeric()) {
                md.dependencies.push(item.to_string());
            }
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim().trim_matches(['"', '\'']).to_string();
        if v.is_empty() {
            continue;
        }
        match k.trim() {
            "name" => {
                set_if(&mut md.mod_name, Some(v.clone()));
                set_if(&mut md.mod_id, Some(v));
            }
            "version" => {
                set_if(&mut md.version, Some(v));
            }
            "description" => {
                set_if(&mut md.description, Some(v));
            }
            "main" => md.entrypoints.push(format!("main: {v}")),
            "author" => md.authors.push(v),
            "depend" | "softdepend" => md.dependencies.push(v),
            _ => {}
        }
    }
}

fn str_of(v: Option<&serde_json::Value>) -> Option<String> {
    v.and_then(|x| x.as_str()).map(|s| s.to_string())
}

fn set_if(dst: &mut String, val: Option<String>) -> bool {
    if dst.is_empty() {
        if let Some(v) = val {
            if !v.is_empty() {
                *dst = v;
                return true;
            }
        }
    }
    false
}

fn toml_value(line: &str) -> Option<String> {
    let (_, rest) = line.split_once('=')?;
    Some(rest.trim().trim_matches(['"', '\'']).to_string())
}

fn toml_first(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with(key) {
            if let Some((k, _)) = t.split_once('=') {
                if k.trim() == key {
                    return toml_value(t).filter(|s| !s.is_empty());
                }
            }
        }
    }
    None
}

fn pretty_json(content: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| content.to_string()),
        Err(_) => content.to_string(),
    }
}
