export interface Theme {
  preset: string;
  accent: string;
  text: string;
  bgImage: string | null;
  bgDim: number;
}

export interface Preset {
  id: string;
  label: string;
  accent: string;
  text: string;
}

export const PRESETS: Preset[] = [
  { id: "amber", label: "Amber", accent: "#e8a13a", text: "#e6e7ea" },
  { id: "signal", label: "Signal", accent: "#3ad19a", text: "#e6e7ea" },
  { id: "ice", label: "Ice", accent: "#5aa6e8", text: "#e7ebf0" },
  { id: "crimson", label: "Crimson", accent: "#e3614f", text: "#ece6e6" },
  { id: "violet", label: "Violet", accent: "#9b7de0", text: "#e8e6ee" },
  { id: "mono", label: "Mono", accent: "#aeb4bf", text: "#e9ebef" },
];

export const DEFAULT_THEME: Theme = {
  preset: "amber",
  accent: "#e8a13a",
  text: "#e6e7ea",
  bgImage: null,
  bgDim: 0.84,
};

const KEY = "endecompiler.theme";

function clampHex(v: string, fallback: string): string {
  return /^#[0-9a-fA-F]{6}$/.test(v) ? v : fallback;
}

function mix(hex: string, factor: number): string {
  const n = parseInt(hex.slice(1), 16);
  const r = Math.round(((n >> 16) & 255) * factor);
  const g = Math.round(((n >> 8) & 255) * factor);
  const b = Math.round((n & 255) * factor);
  return `rgb(${r}, ${g}, ${b})`;
}

function dimText(hex: string, factor: number): string {
  const n = parseInt(hex.slice(1), 16);
  const base = 0x16;
  const r = Math.round(((n >> 16) & 255) * factor + base * (1 - factor));
  const g = Math.round(((n >> 8) & 255) * factor + base * (1 - factor));
  const b = Math.round((n & 255) * factor + base * (1 - factor));
  return `rgb(${r}, ${g}, ${b})`;
}

export function applyTheme(t: Theme) {
  const root = document.documentElement.style;
  const accent = clampHex(t.accent, DEFAULT_THEME.accent);
  const text = clampHex(t.text, DEFAULT_THEME.text);
  root.setProperty("--accent", accent);
  root.setProperty("--accent-dim", mix(accent, 0.52));
  root.setProperty("--text", text);
  root.setProperty("--text-dim", dimText(text, 0.62));
  root.setProperty("--text-faint", dimText(text, 0.4));

  const layer = document.getElementById("bg-layer");
  if (layer) {
    if (t.bgImage) {
      layer.style.backgroundImage = `linear-gradient(rgba(10,11,14,${t.bgDim}), rgba(10,11,14,${t.bgDim})), url("${t.bgImage}")`;
      layer.style.opacity = "1";
      document.body.classList.add("has-bg");
    } else {
      layer.style.backgroundImage = "none";
      layer.style.opacity = "0";
      document.body.classList.remove("has-bg");
    }
  }
}

export function loadTheme(): Theme {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULT_THEME };
    return { ...DEFAULT_THEME, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT_THEME };
  }
}

export function saveTheme(t: Theme) {
  try {
    localStorage.setItem(KEY, JSON.stringify(t));
  } catch {
  }
}
