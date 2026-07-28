import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, rename, rm, writeFile } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import Database from "better-sqlite3";

import type { InspectionStatusResult, InspectResult } from "../domain/verdict.js";

const DATABASE_FILE = "skillseal.sqlite3";

export class InspectionStoreError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "InspectionStoreError";
    this.code = code;
  }
}

function projectRoot(): string {
  return fileURLToPath(new URL("../../", import.meta.url));
}

function defaultDataDirectory(): string {
  return process.env.SKILLSEAL_DATA_DIR || join(projectRoot(), ".skillseal-data");
}

function assertWithin(root: string, target: string): void {
  const rootPath = resolve(root) + sep;
  const targetPath = resolve(target) + sep;
  if (!targetPath.startsWith(rootPath)) {
    throw new InspectionStoreError("UNSAFE_EVIDENCE_PATH", "inspection evidence path escaped the data directory.");
  }
}

export function newInspectionId(createdAt: string): string {
  const timestamp = createdAt.replace(/[-:.TZ]/g, "").slice(0, 14);
  return `ins_${timestamp}_${randomBytes(6).toString("hex")}`;
}

function initializeDatabase(database: Database.Database): void {
  database.pragma("journal_mode = WAL");
  database.pragma("synchronous = FULL");
  database.pragma("foreign_keys = ON");
  database.pragma("busy_timeout = 5000");
  database.exec(`
    CREATE TABLE IF NOT EXISTS inspections (
      id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      cluster TEXT NOT NULL CHECK (cluster IN ('devnet', 'mainnet-beta')),
      asset TEXT NOT NULL,
      sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
      compressed_bytes INTEGER NOT NULL CHECK (compressed_bytes >= 0),
      frozen INTEGER NOT NULL CHECK (frozen IN (0, 1)),
      publisher TEXT NOT NULL,
      verdict TEXT NOT NULL CHECK (verdict IN ('DENY', 'REVIEW_BLOCKED', 'PASS_REQUIRES_APPROVAL')),
      install_eligible INTEGER NOT NULL CHECK (install_eligible IN (0, 1)),
      payload_path TEXT NOT NULL,
      evidence_json TEXT NOT NULL,
      consumed_at TEXT,
      CHECK ((verdict = 'PASS_REQUIRES_APPROVAL' AND install_eligible = 1)
          OR (verdict != 'PASS_REQUIRES_APPROVAL' AND install_eligible = 0))
    );
    CREATE INDEX IF NOT EXISTS inspections_asset_created
      ON inspections(cluster, asset, created_at DESC);
  `);
}

export async function persistInspection(input: Readonly<{
  result: InspectResult;
  compressedPayload: Uint8Array;
  dataDirectory?: string;
}>): Promise<void> {
  const { result, compressedPayload } = input;
  const actualHash = createHash("sha256").update(compressedPayload).digest("hex");
  if (actualHash !== result.payload.sha256 || compressedPayload.byteLength !== result.payload.compressedBytes) {
    throw new InspectionStoreError(
      "EVIDENCE_PAYLOAD_MISMATCH",
      "refusing to persist payload bytes that do not match the inspection verdict.",
    );
  }
  if (!/^ins_[0-9]{14}_[0-9a-f]{12}$/.test(result.inspectionId)) {
    throw new InspectionStoreError("INVALID_INSPECTION_ID", "inspection id does not match the local format.");
  }

  const dataDirectory = resolve(input.dataDirectory ?? defaultDataDirectory());
  const inspectionsDirectory = join(dataDirectory, "inspections");
  await mkdir(inspectionsDirectory, { recursive: true, mode: 0o700 });
  await chmod(dataDirectory, 0o700);
  await chmod(inspectionsDirectory, 0o700);

  const staging = await mkdtemp(join(dataDirectory, "inspection-staging-"));
  const finalDirectory = join(inspectionsDirectory, result.inspectionId);
  assertWithin(dataDirectory, staging);
  assertWithin(inspectionsDirectory, finalDirectory);
  const payloadFile = join(staging, "payload.tar.gz");
  const evidenceFile = join(staging, "evidence.json");
  const relativePayload = relative(dataDirectory, join(finalDirectory, "payload.tar.gz"));
  let renamed = false;

  try {
    await writeFile(payloadFile, compressedPayload, { mode: 0o600, flag: "wx" });
    await writeFile(evidenceFile, `${JSON.stringify(result, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    await rename(staging, finalDirectory);
    renamed = true;

    const databasePath = join(dataDirectory, DATABASE_FILE);
    const database = new Database(databasePath);
    try {
      initializeDatabase(database);
      database
        .prepare(
          `INSERT INTO inspections (
             id, created_at, expires_at, cluster, asset, sha256, compressed_bytes,
             frozen, publisher, verdict, install_eligible, payload_path, evidence_json
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          result.inspectionId,
          result.createdAt,
          result.expiresAt,
          result.cluster,
          result.asset,
          result.payload.sha256,
          result.payload.compressedBytes,
          result.chainState.frozen ? 1 : 0,
          result.trustPolicy.publisher,
          result.verdict,
          result.installEligible ? 1 : 0,
          relativePayload,
          JSON.stringify(result),
        );
    } finally {
      database.close();
      await chmod(databasePath, 0o600);
    }
  } catch (error: unknown) {
    if (renamed) await rm(finalDirectory, { recursive: true, force: true });
    if (error instanceof InspectionStoreError) throw error;
    throw new InspectionStoreError("INSPECTION_PERSIST_FAILED", "failed to persist the inspection atomically.");
  } finally {
    if (!renamed) await rm(staging, { recursive: true, force: true });
  }
}

type InspectionRow = Readonly<{
  id: string;
  created_at: string;
  expires_at: string;
  cluster: "devnet" | "mainnet-beta";
  asset: string;
  sha256: string;
  compressed_bytes: number;
  frozen: 0 | 1;
  publisher: string;
  verdict: "DENY" | "REVIEW_BLOCKED" | "PASS_REQUIRES_APPROVAL";
  install_eligible: 0 | 1;
  consumed_at: string | null;
}>;

type InstallationRow = InspectionRow &
  Readonly<{
    payload_path: string;
    evidence_json: string;
  }>;

export type InstallationClaim = Readonly<{
  inspectionId: string;
  consumedAt: string;
  cluster: "devnet" | "mainnet-beta";
  asset: string;
  sha256: string;
  compressedBytes: number;
  publisher: string;
  payloadPath: string;
  evidenceJson: string;
}>;

export function claimInspectionForInstall(
  inspectionId: string,
  options: Readonly<{ dataDirectory?: string; now?: Date }> = {},
): InstallationClaim {
  if (!/^ins_[0-9]{14}_[0-9a-f]{12}$/.test(inspectionId)) {
    throw new InspectionStoreError("INVALID_INSPECTION_ID", "inspection id does not match the local format.");
  }
  const dataDirectory = resolve(options.dataDirectory ?? defaultDataDirectory());
  const databasePath = join(dataDirectory, DATABASE_FILE);
  let database: Database.Database;
  try {
    database = new Database(databasePath, { fileMustExist: true });
    database.pragma("busy_timeout = 5000");
  } catch {
    throw new InspectionStoreError("INSPECTION_STORE_UNAVAILABLE", "inspection database is not available.");
  }

  try {
    const now = options.now ?? new Date();
    const consumedAt = now.toISOString();
    const claim = database.transaction(() => {
      const row = database
        .prepare(
          `SELECT id, created_at, expires_at, cluster, asset, sha256, compressed_bytes,
                  frozen, publisher, verdict, install_eligible, consumed_at,
                  payload_path, evidence_json
             FROM inspections WHERE id = ?`,
        )
        .get(inspectionId) as InstallationRow | undefined;
      if (row === undefined) {
        throw new InspectionStoreError("INSPECTION_NOT_FOUND", "inspection id was not found.");
      }
      if (row.consumed_at !== null) {
        throw new InspectionStoreError("RECEIPT_CONSUMED", "inspection receipt has already been consumed.");
      }
      if (now.getTime() >= Date.parse(row.expires_at)) {
        throw new InspectionStoreError("RECEIPT_EXPIRED", "inspection receipt has expired.");
      }
      if (
        row.verdict !== "PASS_REQUIRES_APPROVAL" ||
        row.install_eligible !== 1 ||
        row.frozen !== 1
      ) {
        throw new InspectionStoreError(
          "RECEIPT_NOT_INSTALLABLE",
          "inspection receipt is not eligible for installation.",
        );
      }

      const updated = database
        .prepare(
          `UPDATE inspections
              SET consumed_at = ?
            WHERE id = ?
              AND consumed_at IS NULL
              AND verdict = 'PASS_REQUIRES_APPROVAL'
              AND install_eligible = 1
              AND frozen = 1`,
        )
        .run(consumedAt, inspectionId);
      if (updated.changes !== 1) {
        throw new InspectionStoreError("RECEIPT_CONSUMED", "inspection receipt was consumed concurrently.");
      }
      return row;
    });

    const row = claim.immediate();
    const payloadPath = resolve(dataDirectory, row.payload_path);
    assertWithin(dataDirectory, payloadPath);
    return {
      inspectionId: row.id,
      consumedAt,
      cluster: row.cluster,
      asset: row.asset,
      sha256: row.sha256,
      compressedBytes: row.compressed_bytes,
      publisher: row.publisher,
      payloadPath,
      evidenceJson: row.evidence_json,
    };
  } finally {
    database.close();
  }
}

export function getInspectionStatus(
  inspectionId: string,
  options: Readonly<{ dataDirectory?: string; now?: Date }> = {},
): InspectionStatusResult {
  if (!/^ins_[0-9]{14}_[0-9a-f]{12}$/.test(inspectionId)) {
    throw new InspectionStoreError("INVALID_INSPECTION_ID", "inspection id does not match the local format.");
  }
  const dataDirectory = resolve(options.dataDirectory ?? defaultDataDirectory());
  const databasePath = join(dataDirectory, DATABASE_FILE);
  let database: Database.Database;
  try {
    database = new Database(databasePath, { readonly: true, fileMustExist: true });
  } catch {
    throw new InspectionStoreError("INSPECTION_STORE_UNAVAILABLE", "inspection database is not available.");
  }

  try {
    const row = database
      .prepare(
        `SELECT id, created_at, expires_at, cluster, asset, sha256, compressed_bytes,
                frozen, publisher, verdict, install_eligible, consumed_at
           FROM inspections WHERE id = ?`,
      )
      .get(inspectionId) as InspectionRow | undefined;
    if (row === undefined) {
      throw new InspectionStoreError("INSPECTION_NOT_FOUND", "inspection id was not found.");
    }
    const now = options.now ?? new Date();
    const expired = now.getTime() >= Date.parse(row.expires_at);
    const state =
      row.consumed_at !== null
        ? "CONSUMED"
        : expired
          ? "EXPIRED"
          : row.verdict === "PASS_REQUIRES_APPROVAL"
            ? "PENDING_APPROVAL"
            : "BLOCKED";
    return {
      service: "skillseal",
      version: "0.1.0",
      custody: "T0_READ",
      inspectionId: row.id,
      state,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      expired,
      cluster: row.cluster,
      asset: row.asset,
      sha256: row.sha256,
      compressedBytes: row.compressed_bytes,
      frozen: row.frozen === 1,
      publisher: row.publisher,
      verdict: row.verdict,
      installEligible: row.install_eligible === 1 && !expired && row.consumed_at === null,
      consumedAt: row.consumed_at,
      payloadStored: true,
    };
  } finally {
    database.close();
  }
}
