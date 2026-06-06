import { defineConfig } from "vite";

// Tauri expects a fixed dev port and serves the frontend from `dist`.
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  // Prevent Vite from clearing the screen so Rust/Tauri logs stay visible.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? { protocol: "ws", host, port: 1421 }
      : undefined,
    watch: {
      // Don't watch the Rust side from Vite.
      ignored: ["**/src-tauri/**"],
    },
  },
  // Produce assets Tauri's webview (Edge WebView2 / WKWebView) can consume.
  build: {
    target: "es2022",
    minify: !process.env.TAURI_DEBUG ? "esbuild" : false,
    sourcemap: !!process.env.TAURI_DEBUG,
  },
  envPrefix: ["VITE_", "TAURI_"],
});
