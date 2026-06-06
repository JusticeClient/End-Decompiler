
const paths: Record<string, string> = {
  folder: '<path d="M3 6.5A1.5 1.5 0 0 1 4.5 5h3l1.5 2h5.5A1.5 1.5 0 0 1 16 8.5v6A1.5 1.5 0 0 1 14.5 16h-10A1.5 1.5 0 0 1 3 14.5z"/>',
  "folder-open": '<path d="M3 6.5A1.5 1.5 0 0 1 4.5 5h3l1.5 2h5.5A1.5 1.5 0 0 1 16 8.5"/><path d="M3 8h13.5l-1.7 6.2a1 1 0 0 1-1 .8H4.2a1 1 0 0 1-1-.8z"/>',
  file: '<path d="M5 3h6l4 4v10a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M11 3v4h4"/>',
  class: '<rect x="4" y="4" width="12" height="12" rx="1"/><path d="M7.5 8.5h5M7.5 11.5h5"/>',
  cube: '<path d="M10 3 16 6.5v7L10 17 4 13.5v-7z"/><path d="m4 6.5 6 3.5 6-3.5M10 10v7"/>',
  open: '<path d="M3 5h5l1.5 2H17v8a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/>',
  play: '<path d="M6 4l9 6-9 6z"/>',
  shield: '<path d="M10 3l6 2v4c0 4-2.6 6.6-6 8-3.4-1.4-6-4-6-8V5z"/>',
  search: '<circle cx="8.5" cy="8.5" r="4.5"/><path d="m12 12 4 4"/>',
  download: '<path d="M10 3v9m0 0 3.5-3.5M10 12 6.5 8.5"/><path d="M4 15h12"/>',
  code: '<path d="m7 7-4 3 4 3M13 7l4 3-4 3"/>',
  binary: '<rect x="4" y="3" width="5" height="6" rx="1"/><rect x="11" y="11" width="5" height="6" rx="1"/><path d="M9 11h2v6M4 17h5M11 3h5"/>',
  copy: '<rect x="7" y="7" width="9" height="9" rx="1"/><path d="M4 12V5a1 1 0 0 1 1-1h7"/>',
  scan: '<path d="M4 7V5a1 1 0 0 1 1-1h2M13 4h2a1 1 0 0 1 1 1v2M16 13v2a1 1 0 0 1-1 1h-2M7 16H5a1 1 0 0 1-1-1v-2"/><path d="M4 10h12"/>',
  alert: '<path d="M10 3 18 16H2z"/><path d="M10 8v4M10 14h.01"/>',
  x: '<path d="m5 5 10 10M15 5 5 15"/>',
  min: '<path d="M4 10h12"/>',
  max: '<rect x="4" y="4" width="12" height="12" rx="1"/>',
  refresh: '<path d="M15 7a6 6 0 1 0 1 4"/><path d="M16 4v3h-3"/>',
  list: '<path d="M6 6h10M6 10h10M6 14h10M3 6h.01M3 10h.01M3 14h.01"/>',
  info: '<circle cx="10" cy="10" r="7"/><path d="M10 9v4M10 7h.01"/>',
  chevron: '<path d="m7 5 5 5-5 5"/>',
  settings: '<circle cx="10" cy="10" r="2.6"/><path d="M10 2.5v2M10 15.5v2M2.5 10h2M15.5 10h2M4.7 4.7l1.4 1.4M13.9 13.9l1.4 1.4M15.3 4.7l-1.4 1.4M6.1 13.9l-1.4 1.4"/>',
  image: '<rect x="3" y="4" width="14" height="12" rx="1.5"/><circle cx="7.5" cy="8.5" r="1.5"/><path d="m4 14 4-3.5 3 2.5 2.5-2 2.5 3"/>',
  reset: '<path d="M4 10a6 6 0 1 1 1.8 4.3"/><path d="M4 6v3h3"/>',
};

export function icon(name: string, cls = "icon"): string {
  const p = paths[name] ?? paths.file;
  return `<svg class="${cls}" viewBox="0 0 20 20" aria-hidden="true">${p}</svg>`;
}

export function iconEl(name: string, cls = "icon"): SVGElement {
  const wrap = document.createElement("div");
  wrap.innerHTML = icon(name, cls);
  return wrap.firstElementChild as SVGElement;
}
