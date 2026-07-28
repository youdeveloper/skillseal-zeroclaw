import assert from "node:assert/strict";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { ArchiveScanError, scanTarGzip } from "../dist/archive/scan.js";

function octal(value, length) {
  return value.toString(8).padStart(length - 1, "0") + "\0";
}

function header({ path, type = "file", content = Buffer.alloc(0), mode }) {
  const block = Buffer.alloc(512);
  block.write(path, 0, 100, "utf8");
  block.write(octal(mode ?? (type === "directory" ? 0o755 : 0o644), 8), 100);
  block.write(octal(0, 8), 108);
  block.write(octal(0, 8), 116);
  block.write(octal(type === "directory" ? 0 : content.length, 12), 124);
  block.write(octal(0, 12), 136);
  block.write("        ", 148);
  block.write(type === "file" ? "0" : type === "directory" ? "5" : type, 156);
  block.write("ustar\0", 257);
  block.write("00", 263);
  let checksum = 0;
  for (const byte of block) checksum += byte;
  block.write(checksum.toString(8).padStart(6, "0") + "\0 ", 148);
  return block;
}

function archive(entries) {
  const blocks = [];
  for (const entry of entries) {
    const content = entry.content ?? Buffer.alloc(0);
    blocks.push(header({ ...entry, content }));
    if (entry.type !== "directory" && content.length > 0) {
      blocks.push(content);
      const padding = (512 - (content.length % 512)) % 512;
      if (padding > 0) blocks.push(Buffer.alloc(padding));
    }
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks), { level: 9 });
}

test("safe ustar archive passes bounded in-memory preflight", () => {
  const compressed = archive([
    { path: "scripts/", type: "directory" },
    { path: "SKILL.md", content: Buffer.from("---\nname: safe\n---\n") },
    { path: "scripts/read.mjs", content: Buffer.from("export const value = 1;\n") },
  ]);
  const scanned = scanTarGzip(compressed, "SKILL.md");

  assert.equal(scanned.summary.safety, "VERIFIED");
  assert.equal(scanned.summary.files, 2);
  assert.equal(scanned.summary.directories, 1);
  assert.equal(scanned.summary.entrypointPresent, true);
  assert.deepEqual([...scanned.files.keys()], ["SKILL.md", "scripts/read.mjs"]);
});

test("path traversal is rejected", () => {
  const compressed = archive([{ path: "../escape", content: Buffer.from("hostile") }]);
  assert.throws(
    () => scanTarGzip(compressed, "SKILL.md"),
    (error) => error instanceof ArchiveScanError && error.code === "UNSAFE_PATH",
  );
});

test("symbolic links are rejected", () => {
  const compressed = archive([{ path: "SKILL.md", type: "2" }]);
  assert.throws(
    () => scanTarGzip(compressed, "SKILL.md"),
    (error) => error instanceof ArchiveScanError && error.code === "UNSUPPORTED_ENTRY_TYPE",
  );
});

test("missing declared entrypoint is rejected", () => {
  const compressed = archive([{ path: "README.md", content: Buffer.from("no skill") }]);
  assert.throws(
    () => scanTarGzip(compressed, "SKILL.md"),
    (error) => error instanceof ArchiveScanError && error.code === "MISSING_ENTRYPOINT",
  );
});
