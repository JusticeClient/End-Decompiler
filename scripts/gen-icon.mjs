
import { deflateSync } from "node:zlib";
import { writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SIZE = 1024;

const BG = [0x0c, 0x0d, 0x10, 0xff];
const PANEL = [0x15, 0x16, 0x1b, 0xff];
const AMBER = [0xe8, 0xa1, 0x3a, 0xff];

const buf = Buffer.alloc(SIZE * SIZE * 4);

function px(x, y, c) {
  if (x < 0 || y < 0 || x >= SIZE || y >= SIZE) return;
  const i = (y * SIZE + x) * 4;
  buf[i] = c[0];
  buf[i + 1] = c[1];
  buf[i + 2] = c[2];
  buf[i + 3] = c[3];
}
function rect(x0, y0, w, h, c) {
  for (let y = y0; y < y0 + h; y++) for (let x = x0; x < x0 + w; x++) px(x, y, c);
}

rect(0, 0, SIZE, SIZE, BG);
rect(96, 96, SIZE - 192, SIZE - 192, PANEL);
const f = 10;
rect(96, 96, SIZE - 192, f, AMBER);
rect(96, SIZE - 96 - f, SIZE - 192, f, AMBER);
rect(96, 96, f, SIZE - 192, AMBER);
rect(SIZE - 96 - f, 96, f, SIZE - 192, AMBER);

const t = 70;
const ex = 320,
  ey = 290,
  eh = 444,
  ew = 360;
rect(ex, ey, t, eh, AMBER);
rect(ex, ey, ew, t, AMBER);
rect(ex, ey + eh / 2 - t / 2, ew - 60, t, AMBER);
rect(ex, ey + eh - t, ew, t, AMBER);

function crc32(b) {
  let c = ~0;
  for (let i = 0; i < b.length; i++) {
    c ^= b[i];
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const t = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([t, data])), 0);
  return Buffer.concat([len, t, data, crc]);
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(SIZE, 0);
ihdr.writeUInt32BE(SIZE, 4);
ihdr[8] = 8;
ihdr[9] = 6;
const raw = Buffer.alloc((SIZE * 4 + 1) * SIZE);
for (let y = 0; y < SIZE; y++) {
  raw[y * (SIZE * 4 + 1)] = 0;
  buf.copy(raw, y * (SIZE * 4 + 1) + 1, y * SIZE * 4, (y + 1) * SIZE * 4);
}
const png = Buffer.concat([
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
  chunk("IHDR", ihdr),
  chunk("IDAT", deflateSync(raw, { level: 9 })),
  chunk("IEND", Buffer.alloc(0)),
]);

const out = join(__dirname, "..", "src-tauri", "icon-source.png");
await writeFile(out, png);
console.log(`[icon] wrote ${out} (${(png.length / 1024).toFixed(0)} KiB)`);
