
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JavaInfo {
    pub found: bool,
    pub version: String,
    pub major: u32,
    pub java_path: String,
    pub usable: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassEntry {
    pub internal_name: String,
    pub size: u64,
    pub inner: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceEntry {
    pub path: String,
    pub size: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveInfo {
    pub id: u64,
    pub name: String,
    pub path: String,
    pub class_count: usize,
    pub resource_count: usize,
    pub total_size: u64,
    pub classes: Vec<ClassEntry>,
    pub resources: Vec<ResourceEntry>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecompileResult {
    pub internal_name: String,
    pub mode: String,
    pub language: String,
    pub code: String,
    pub decompiler: String,
    pub fell_back: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StringEntry {
    pub value: String,
    pub class: String,
    pub tag: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn weight(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 4,
            Severity::High => 9,
            Severity::Critical => 16,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub category: String,
    pub class: String,
    pub line: u32,
    pub snippet: String,
    pub why: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub level: String,
    pub label: String,
    pub score: u32,
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisReport {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    pub category_counts: Vec<(String, usize)>,
    pub severity_counts: Vec<(String, usize)>,
    pub classes_scanned: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub manifest: Vec<(String, String)>,
    pub loader: String,
    pub mod_id: String,
    pub mod_name: String,
    pub version: String,
    pub description: String,
    pub authors: Vec<String>,
    pub entrypoints: Vec<String>,
    pub mixins: Vec<String>,
    pub dependencies: Vec<String>,
    pub raw_descriptors: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
    pub perms: String,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeImport {
    pub dll: String,
    pub functions: Vec<String>,
    pub flagged: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DllReport {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub arch: String,
    pub subsystem: String,
    pub is_dotnet: bool,
    pub signed: bool,
    pub timestamp: String,
    pub image_size: u64,
    pub entry_point: u64,
    pub section_count: usize,
    pub import_count: usize,
    pub export_count: usize,
    pub sections: Vec<PeSection>,
    pub imports: Vec<PeImport>,
    pub exports: Vec<String>,
    pub string_count: usize,
    pub analysis: AnalysisReport,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
    pub class: String,
    pub line: u32,
    pub text: String,
}
