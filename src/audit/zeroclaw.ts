import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import type { ScannedArchive } from "../archive/scan.js";

const execFileAsync = promisify(execFile);
const AUDIT_TIMEOUT_MS = 20_000;
const AUDIT_OUTPUT_BYTES = 65_536;

export class NativeAuditError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "NativeAuditError";
    this.code = code;
  }
}

type AuditCommandResult = Readonly<{ stdout: string; stderr: string }>;
type AuditRunner = (sourceDirectory: string, configDirectory: string) => Promise<AuditCommandResult>;

function projectRoot(): string {
  return fileURLToPath(new URL("../../", import.meta.url));
}

function assertWithin(root: string, target: string): void {
  const normalizedRoot = resolve(root) + sep;
  const normalizedTarget = resolve(target) + sep;
  if (!normalizedTarget.startsWith(normalizedRoot)) {
    throw new NativeAuditError("UNSAFE_QUARANTINE_PATH", "quarantine path escaped the configured data directory.");
  }
}

function defaultDataDirectory(): string {
  return process.env.SKILLSEAL_DATA_DIR || join(projectRoot(), ".skillseal-data");
}

function defaultZeroClawBinary(): string {
  return (
    process.env.SKILLSEAL_ZEROCLAW_BIN ||
    join(projectRoot(), ".tools", "zeroclaw-v0.8.3", "zeroclaw")
  );
}

async function defaultRunner(
  sourceDirectory: string,
  configDirectory: string,
): Promise<AuditCommandResult> {
  const binary = defaultZeroClawBinary();
  try {
    await access(binary, constants.X_OK);
  } catch {
    throw new NativeAuditError(
      "ZEROCLAW_BINARY_UNAVAILABLE",
      "ZeroClaw binary is missing or not executable; set SKILLSEAL_ZEROCLAW_BIN.",
    );
  }

  try {
    const result = await execFileAsync(
      binary,
      ["--config-dir", configDirectory, "skills", "audit", sourceDirectory],
      {
        timeout: AUDIT_TIMEOUT_MS,
        maxBuffer: AUDIT_OUTPUT_BYTES,
        encoding: "utf8",
        windowsHide: true,
      },
    );
    return { stdout: result.stdout, stderr: result.stderr };
  } catch (error: unknown) {
    const timedOut =
      error instanceof Error && "killed" in error && (error as Error & { killed: unknown }).killed === true;
    if (timedOut) {
      throw new NativeAuditError("ZEROCLAW_AUDIT_TIMEOUT", "ZeroClaw native audit exceeded 20 seconds.");
    }
    throw new NativeAuditError("ZEROCLAW_AUDIT_FAILED", "ZeroClaw native audit rejected the quarantined skill.");
  }
}

async function materializeArchive(scanned: ScannedArchive, destination: string): Promise<void> {
  for (const entry of scanned.summary.inventory) {
    const target = join(destination, ...entry.path.split("/"));
    assertWithin(destination, target);
    if (entry.type === "directory") {
      await mkdir(target, { recursive: true, mode: 0o700 });
      continue;
    }
    const content = scanned.files.get(entry.path);
    if (content === undefined) {
      throw new NativeAuditError("MISSING_SCANNED_FILE", `preflight content is missing for ${entry.path}.`);
    }
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    await writeFile(target, content, { mode: 0o600, flag: "wx" });
  }
}

export async function runZeroClawNativeAudit(
  scanned: ScannedArchive,
  options: Readonly<{ dataDirectory?: string; runner?: AuditRunner }> = {},
): Promise<Readonly<{ tool: "zeroclaw skills audit"; status: "PASSED"; filesScanned: number }>> {
  const dataDirectory = resolve(options.dataDirectory ?? defaultDataDirectory());
  await mkdir(dataDirectory, { recursive: true, mode: 0o700 });
  const quarantine = await mkdtemp(join(dataDirectory, "quarantine-"));
  const auditConfig = await mkdtemp(join(dataDirectory, "audit-config-"));
  assertWithin(dataDirectory, quarantine);
  assertWithin(dataDirectory, auditConfig);

  try {
    await materializeArchive(scanned, quarantine);
    const runner = options.runner ?? defaultRunner;
    const result = await runner(quarantine, auditConfig);
    const combined = `${result.stdout}\n${result.stderr}`;
    const match = /Skill audit passed .*\(([0-9]+) files scanned\)\./.exec(combined);
    if (match?.[1] === undefined) {
      throw new NativeAuditError(
        "UNRECOGNIZED_AUDIT_OUTPUT",
        "ZeroClaw exited successfully but did not emit the expected audit receipt.",
      );
    }
    const filesScanned = Number(match[1]);
    if (!Number.isSafeInteger(filesScanned) || filesScanned < scanned.summary.files) {
      throw new NativeAuditError(
        "INCOMPLETE_AUDIT_RECEIPT",
        "ZeroClaw audit receipt reports fewer files than the preflight inventory.",
      );
    }
    return { tool: "zeroclaw skills audit", status: "PASSED", filesScanned };
  } finally {
    await rm(quarantine, { recursive: true, force: true });
    await rm(auditConfig, { recursive: true, force: true });
  }
}
