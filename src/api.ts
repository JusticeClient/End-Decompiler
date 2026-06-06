
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AnalysisReport,
  ArchiveInfo,
  DecompileProgress,
  DecompileResult,
  DllReport,
  JavaInfo,
  Metadata,
  SearchHit,
  StringEntry,
} from "./types";

export const api = {
  detectJava: () => invoke<JavaInfo>("detect_java"),

  openArchive: (path: string) => invoke<ArchiveInfo>("open_archive", { path }),

  closeArchive: (id: number) => invoke<void>("close_archive", { id }),

  decompileClass: (id: number, internalName: string, mode: "source" | "bytecode") =>
    invoke<DecompileResult>("decompile_class", { id, internalName, mode }),

  decompileAll: (id: number) => invoke<number>("decompile_all", { id }),

  getStrings: (id: number) => invoke<StringEntry[]>("get_strings", { id }),

  getMetadata: (id: number) => invoke<Metadata>("get_metadata", { id }),

  readResource: (id: number, path: string) =>
    invoke<string>("read_resource", { id, path }),

  analyzeArchive: (id: number) => invoke<AnalysisReport>("analyze_archive", { id }),

  searchAll: (id: number, query: string, caseSensitive: boolean) =>
    invoke<SearchHit[]>("search_all", { id, query, caseSensitive }),

  exportReport: (id: number, format: "markdown" | "json") =>
    invoke<string>("export_report", { id, format }),

  exportSources: (id: number, dest: string) =>
    invoke<number>("export_sources", { id, dest }),

  writeFile: (path: string, content: string) =>
    invoke<void>("write_file", { path, content }),

  readImageDataUrl: (path: string) =>
    invoke<string>("read_image_data_url", { path }),

  analyzeDll: (path: string) => invoke<DllReport>("analyze_dll", { path }),

  getDllStrings: (path: string) => invoke<StringEntry[]>("get_dll_strings", { path }),

  disassembleDll: (path: string) => invoke<string>("disassemble_dll", { path }),

  decompileDotnet: (path: string) => invoke<string>("decompile_dotnet", { path }),
};

export function onDecompileProgress(
  cb: (p: DecompileProgress) => void
): Promise<UnlistenFn> {
  return listen<DecompileProgress>("decompile-progress", (e) => cb(e.payload));
}
