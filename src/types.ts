
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface JavaInfo {
  found: boolean;
  version: string;
  major: number;
  javaPath: string;
  usable: boolean;
  note: string;
}

export interface ClassEntry {
  internalName: string;
  size: number;
  inner: boolean;
}

export interface ResourceEntry {
  path: string;
  size: number;
  kind: string;
}

export interface ArchiveInfo {
  id: number;
  name: string;
  path: string;
  classCount: number;
  resourceCount: number;
  totalSize: number;
  classes: ClassEntry[];
  resources: ResourceEntry[];
}

export interface DecompileResult {
  internalName: string;
  mode: "source" | "bytecode";
  language: "java" | "bytecode";
  code: string;
  decompiler: string;
  fellBack: boolean;
  note: string;
}

export interface StringEntry {
  value: string;
  class: string;
  tag: "url" | "ip" | "path" | "base64" | "plain";
}

export interface Finding {
  id: string;
  severity: Severity;
  category: string;
  class: string;
  line: number;
  snippet: string;
  why: string;
}

export interface Verdict {
  level: "clean" | "suspicious" | "likely_malicious" | "malicious";
  label: string;
  score: number;
  reasoning: string;
}

export interface AnalysisReport {
  verdict: Verdict;
  findings: Finding[];
  categoryCounts: [string, number][];
  severityCounts: [string, number][];
  classesScanned: number;
}

export interface Metadata {
  manifest: [string, string][];
  loader: string;
  modId: string;
  modName: string;
  version: string;
  description: string;
  authors: string[];
  entrypoints: string[];
  mixins: string[];
  dependencies: string[];
  rawDescriptors: [string, string][];
}

export interface SearchHit {
  class: string;
  line: number;
  text: string;
}

export interface PeSection {
  name: string;
  virtualSize: number;
  rawSize: number;
  entropy: number;
  perms: string;
  suspicious: boolean;
}

export interface PeImport {
  dll: string;
  functions: string[];
  flagged: number;
}

export interface DllReport {
  name: string;
  path: string;
  kind: string;
  arch: string;
  subsystem: string;
  isDotnet: boolean;
  signed: boolean;
  timestamp: string;
  imageSize: number;
  entryPoint: number;
  sectionCount: number;
  importCount: number;
  exportCount: number;
  sections: PeSection[];
  imports: PeImport[];
  exports: string[];
  stringCount: number;
  analysis: AnalysisReport;
}

export interface DecompileProgress {
  id: number;
  done: number;
  total: number;
  current: string;
}
