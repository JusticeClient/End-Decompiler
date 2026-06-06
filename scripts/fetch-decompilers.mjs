
import { mkdir, writeFile, stat, rm, cp, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const RES_DIR = join(__dirname, "..", "src-tauri", "resources");

const MAVEN = "https://repo1.maven.org/maven2";

const DEPS = [
  { name: "Vineflower", group: "org/vineflower", artifact: "vineflower", out: "vineflower.jar" },
  { name: "CFR", group: "org/benf", artifact: "cfr", out: "cfr.jar" },
];

async function fetchText(url) {
  const res = await fetch(url, { headers: { "User-Agent": "endecompiler-build" } });
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return res.text();
}

async function fetchBuffer(url) {
  const res = await fetch(url, { headers: { "User-Agent": "endecompiler-build" } });
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

async function latestVersion(dep) {
  const metaUrl = `${MAVEN}/${dep.group}/${dep.artifact}/maven-metadata.xml`;
  const xml = await fetchText(metaUrl);
  const release = xml.match(/<release>([^<]+)<\/release>/)?.[1];
  if (release) return release;
  const versions = [...xml.matchAll(/<version>([^<]+)<\/version>/g)]
    .map((m) => m[1])
    .filter((v) => !/-(SNAPSHOT|alpha|beta|rc)/i.test(v));
  if (!versions.length) throw new Error(`no stable version for ${dep.artifact}`);
  return versions[versions.length - 1];
}

async function exists(p) {
  try {
    const s = await stat(p);
    return s.size > 0;
  } catch {
    return false;
  }
}

async function fetchIlspy(force) {
  const dir = join(RES_DIR, "ilspycmd");
  if (!force && (await exists(join(dir, "ilspycmd.dll")))) {
    console.log("[fetch] ilspycmd: already present, skipping");
    return;
  }
  try {
    const idx = await fetchText("https://api.nuget.org/v3-flatcontainer/ilspycmd/index.json");
    const versions = JSON.parse(idx).versions.filter(
      (v) => /^8\./.test(v) && !/-(preview|rc|beta|alpha)/i.test(v)
    );
    const ver = versions[versions.length - 1];
    console.log(`[fetch] ilspycmd ${ver}`);
    const buf = await fetchBuffer(
      `https://api.nuget.org/v3-flatcontainer/ilspycmd/${ver}/ilspycmd.${ver}.nupkg`
    );
    const tmp = join(tmpdir(), `ilspy_${ver}_${Math.floor(performance.now())}`);
    await mkdir(tmp, { recursive: true });
    const zipPath = join(tmp, "ilspy.zip");
    await writeFile(zipPath, buf);
    const ex = join(tmp, "x");
    await mkdir(ex, { recursive: true });
    if (process.platform === "win32") {
      execFileSync("powershell", [
        "-NoProfile",
        "-Command",
        `Expand-Archive -LiteralPath '${zipPath}' -DestinationPath '${ex}' -Force`,
      ]);
    } else {
      execFileSync("unzip", ["-o", zipPath, "-d", ex]);
    }
    const toolDir = await findToolDir(join(ex, "tools"));
    if (!toolDir) throw new Error("ilspycmd.dll not found in package");
    await rm(dir, { recursive: true, force: true });
    await mkdir(dir, { recursive: true });
    await cp(toolDir, dir, { recursive: true });
    console.log(`[fetch] ilspycmd: extracted -> ${dir}`);
  } catch (err) {
    console.error(`[fetch] ERROR for ilspycmd: ${err.message}`);
    console.error("[fetch] .NET decompilation will be unavailable until ilspycmd is present.");
  }
}

async function findToolDir(root) {
  let found = null;
  async function walk(d) {
    let entries;
    try {
      entries = await readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    if (entries.some((e) => e.isFile() && e.name === "ilspycmd.dll")) {
      found = d;
      return;
    }
    for (const e of entries) {
      if (e.isDirectory() && !found) await walk(join(d, e.name));
    }
  }
  await walk(root);
  return found;
}

async function main() {
  await mkdir(RES_DIR, { recursive: true });
  const force = process.argv.includes("--force");
  await fetchIlspy(force);

  for (const dep of DEPS) {
    const outPath = join(RES_DIR, dep.out);
    if (!force && (await exists(outPath))) {
      console.log(`[fetch] ${dep.name}: already present, skipping (use --force to refresh)`);
      continue;
    }
    try {
      const version = await latestVersion(dep);
      const jarUrl = `${MAVEN}/${dep.group}/${dep.artifact}/${version}/${dep.artifact}-${version}.jar`;
      console.log(`[fetch] ${dep.name} ${version} <- ${jarUrl}`);
      const buf = await fetchBuffer(jarUrl);
      await writeFile(outPath, buf);
      console.log(`[fetch] ${dep.name}: wrote ${(buf.length / 1024 / 1024).toFixed(1)} MiB -> ${outPath}`);
    } catch (err) {
      console.error(`[fetch] ERROR for ${dep.name}: ${err.message}`);
      console.error(
        `[fetch] Place a ${dep.out} manually in src-tauri/resources/ to continue.`
      );
      process.exitCode = 1;
    }
  }
}

main();
