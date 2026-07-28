import { gunzipSync } from "node:zlib";

import type { ArchiveEntrySummary } from "../domain/verdict.js";

export const MAX_ARCHIVE_BYTES = 1_048_576;
export const MAX_EXPANDED_BYTES = 4_194_304;
export const MAX_ARCHIVE_ENTRIES = 64;
export const MAX_PATH_BYTES = 240;

const TAR_BLOCK_BYTES = 512;
const TAR_END_BYTES = TAR_BLOCK_BYTES * 2;
const utf8 = new TextDecoder("utf-8", { fatal: true });

export class ArchiveScanError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ArchiveScanError";
    this.code = code;
  }
}

export type ScannedArchive = Readonly<{
  summary: Readonly<{
    format: "ustar+gzip";
    safety: "VERIFIED";
    expandedBytes: number;
    entries: number;
    files: number;
    directories: number;
    entrypointPresent: true;
    inventory: readonly ArchiveEntrySummary[];
  }>;
  files: ReadonlyMap<string, Uint8Array>;
}>;

function allZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

function decodeField(block: Uint8Array, start: number, length: number, field: string): string {
  const bytes = block.subarray(start, start + length);
  const nul = bytes.indexOf(0);
  const content = nul === -1 ? bytes : bytes.subarray(0, nul);
  if (nul !== -1 && !bytes.subarray(nul).every((byte) => byte === 0 || byte === 32)) {
    throw new ArchiveScanError("INVALID_TAR_FIELD", `${field} contains bytes after its terminator.`);
  }
  try {
    return utf8.decode(content);
  } catch {
    throw new ArchiveScanError("INVALID_TAR_UTF8", `${field} is not valid UTF-8.`);
  }
}

function parseOctalField(
  block: Uint8Array,
  start: number,
  length: number,
  field: string,
): number {
  const raw = block.subarray(start, start + length);
  if ((raw[0] ?? 0) >= 0x80) {
    throw new ArchiveScanError("UNSUPPORTED_TAR_NUMBER", `${field} uses unsupported base-256 encoding.`);
  }
  const text = Buffer.from(raw).toString("ascii").replace(/[\0 ]+$/g, "").replace(/^ +/g, "");
  if (text === "") return 0;
  if (!/^[0-7]+$/.test(text)) {
    throw new ArchiveScanError("INVALID_TAR_NUMBER", `${field} is not a valid octal value.`);
  }
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value)) {
    throw new ArchiveScanError("INVALID_TAR_NUMBER", `${field} exceeds the safe integer range.`);
  }
  return value;
}

function validateChecksum(block: Uint8Array): void {
  const declared = parseOctalField(block, 148, 8, "header checksum");
  let actual = 0;
  for (let index = 0; index < block.length; index += 1) {
    actual += index >= 148 && index < 156 ? 32 : (block[index] ?? 0);
  }
  if (actual !== declared) {
    throw new ArchiveScanError(
      "TAR_CHECKSUM_MISMATCH",
      `tar header checksum mismatch: declared=${declared}, actual=${actual}.`,
    );
  }
}

function normalizeSafePath(rawName: string, type: "file" | "directory"): string {
  if (rawName.length === 0 || /[\u0000-\u001f\u007f]/.test(rawName)) {
    throw new ArchiveScanError("UNSAFE_PATH", "archive entry path is empty or contains control characters.");
  }
  if (rawName.startsWith("/") || /^[A-Za-z]:/.test(rawName) || rawName.includes("\\")) {
    throw new ArchiveScanError("UNSAFE_PATH", `archive entry is not a portable relative path: ${rawName}`);
  }
  if (Buffer.byteLength(rawName, "utf8") > MAX_PATH_BYTES) {
    throw new ArchiveScanError("PATH_TOO_LONG", `archive entry path exceeds ${MAX_PATH_BYTES} UTF-8 bytes.`);
  }

  const path = type === "directory" && rawName.endsWith("/") ? rawName.slice(0, -1) : rawName;
  const segments = path.split("/");
  if (
    path.length === 0 ||
    segments.some((segment) => segment === "" || segment === "." || segment === "..")
  ) {
    throw new ArchiveScanError("UNSAFE_PATH", `archive entry contains an unsafe path segment: ${rawName}`);
  }
  return path;
}

function assertNoFileDirectoryConflicts(entries: readonly ArchiveEntrySummary[]): void {
  const types = new Map(entries.map((entry) => [entry.path, entry.type]));
  for (const entry of entries) {
    const segments = entry.path.split("/");
    for (let length = 1; length < segments.length; length += 1) {
      const ancestor = segments.slice(0, length).join("/");
      if (types.get(ancestor) === "file") {
        throw new ArchiveScanError(
          "PATH_TYPE_CONFLICT",
          `regular file is also used as a parent directory: ${ancestor}`,
        );
      }
    }
  }
}

export function scanTarGzip(compressed: Uint8Array, entrypoint: string): ScannedArchive {
  if (compressed.byteLength > MAX_ARCHIVE_BYTES) {
    throw new ArchiveScanError(
      "ARCHIVE_TOO_LARGE",
      `compressed archive exceeds the ${MAX_ARCHIVE_BYTES}-byte policy limit.`,
    );
  }

  let tar: Buffer;
  try {
    tar = gunzipSync(compressed, { maxOutputLength: MAX_EXPANDED_BYTES });
  } catch (error: unknown) {
    const code =
      error instanceof Error && "code" in error ? String((error as Error & { code: unknown }).code) : "";
    if (code === "ERR_BUFFER_TOO_LARGE") {
      throw new ArchiveScanError(
        "ARCHIVE_EXPANSION_LIMIT",
        `expanded archive exceeds the ${MAX_EXPANDED_BYTES}-byte policy limit.`,
      );
    }
    throw new ArchiveScanError("INVALID_GZIP", "payload is not a valid bounded gzip stream.");
  }

  if (tar.byteLength < TAR_END_BYTES || tar.byteLength % TAR_BLOCK_BYTES !== 0) {
    throw new ArchiveScanError("INVALID_TAR_SIZE", "tar stream is not block-aligned or lacks end markers.");
  }

  const inventory: ArchiveEntrySummary[] = [];
  const files = new Map<string, Uint8Array>();
  const seen = new Set<string>();
  let offset = 0;
  let foundEnd = false;

  while (offset + TAR_BLOCK_BYTES <= tar.byteLength) {
    const block = tar.subarray(offset, offset + TAR_BLOCK_BYTES);
    if (allZero(block)) {
      const second = tar.subarray(offset + TAR_BLOCK_BYTES, offset + TAR_END_BYTES);
      if (second.byteLength !== TAR_BLOCK_BYTES || !allZero(second)) {
        throw new ArchiveScanError("INVALID_TAR_END", "tar stream has only one zero end block.");
      }
      if (!allZero(tar.subarray(offset + TAR_END_BYTES))) {
        throw new ArchiveScanError("TRAILING_TAR_DATA", "tar stream contains non-zero data after its end markers.");
      }
      foundEnd = true;
      break;
    }

    if (inventory.length >= MAX_ARCHIVE_ENTRIES) {
      throw new ArchiveScanError(
        "TOO_MANY_ENTRIES",
        `archive exceeds the ${MAX_ARCHIVE_ENTRIES}-entry policy limit.`,
      );
    }
    validateChecksum(block);
    if (decodeField(block, 257, 6, "ustar magic") !== "ustar") {
      throw new ArchiveScanError("UNSUPPORTED_TAR_FORMAT", "archive is not in ustar format.");
    }

    const name = decodeField(block, 0, 100, "entry name");
    const prefix = decodeField(block, 345, 155, "entry prefix");
    const rawPath = prefix === "" ? name : `${prefix}/${name}`;
    const size = parseOctalField(block, 124, 12, "entry size");
    const mode = parseOctalField(block, 100, 8, "entry mode");
    if ((mode & 0o7000) !== 0) {
      throw new ArchiveScanError("UNSAFE_MODE", `archive entry has special permission bits: ${rawPath}`);
    }
    const typeByte = block[156] ?? 0;
    const type = typeByte === 0 || typeByte === 48 ? "file" : typeByte === 53 ? "directory" : null;
    if (type === null) {
      const printableType = typeByte === 0 ? "NUL" : String.fromCharCode(typeByte);
      throw new ArchiveScanError(
        "UNSUPPORTED_ENTRY_TYPE",
        `archive entry type '${printableType}' is forbidden: ${rawPath}`,
      );
    }
    if (type === "directory" && size !== 0) {
      throw new ArchiveScanError("INVALID_DIRECTORY_SIZE", `directory entry has non-zero size: ${rawPath}`);
    }

    const path = normalizeSafePath(rawPath, type);
    if (seen.has(path)) {
      throw new ArchiveScanError("DUPLICATE_PATH", `archive contains a duplicate normalized path: ${path}`);
    }
    seen.add(path);

    const dataStart = offset + TAR_BLOCK_BYTES;
    const dataEnd = dataStart + size;
    const nextOffset = dataStart + Math.ceil(size / TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES;
    if (dataEnd > tar.byteLength || nextOffset > tar.byteLength) {
      throw new ArchiveScanError("TRUNCATED_TAR", `archive entry exceeds the tar stream: ${path}`);
    }
    if (!allZero(tar.subarray(dataEnd, nextOffset))) {
      throw new ArchiveScanError("NONZERO_PADDING", `archive entry has non-zero padding bytes: ${path}`);
    }

    inventory.push({ path, type, size, mode });
    if (type === "file") files.set(path, tar.subarray(dataStart, dataEnd));
    offset = nextOffset;
  }

  if (!foundEnd) {
    throw new ArchiveScanError("MISSING_TAR_END", "tar stream does not contain two zero end blocks.");
  }
  assertNoFileDirectoryConflicts(inventory);
  if (!files.has(entrypoint)) {
    throw new ArchiveScanError("MISSING_ENTRYPOINT", `declared entrypoint is not a regular file: ${entrypoint}`);
  }

  const fileCount = inventory.filter((entry) => entry.type === "file").length;
  const directoryCount = inventory.length - fileCount;
  return {
    summary: {
      format: "ustar+gzip",
      safety: "VERIFIED",
      expandedBytes: tar.byteLength,
      entries: inventory.length,
      files: fileCount,
      directories: directoryCount,
      entrypointPresent: true,
      inventory,
    },
    files,
  };
}
