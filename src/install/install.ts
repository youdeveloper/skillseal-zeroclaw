import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  rename,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { ArchiveScanError, MAX_ARCHIVE_BYTES, scanTarGzip } from "../archive/scan.js";
import type { InstallResult, InspectCluster } from "../domain/verdict.js";
import {
  claimInspectionForInstall,
  InspectionStoreError,
  type InstallationClaim,
} from "../store/inspections.js";

const SAFE_SKILL_NAME = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

type Evidence = Readonly<{
  inspectionId: string;
  cluster: InspectCluster;
  asset: string;
  assetOwner: string;
  manifest: Readonly<{
    name: string;
    entrypoint: string;
    permissions: readonly string[];
  }>;
  payload: Readonly<{
    sha256: string;
    compressedBytes: number;
    integrity: "VERIFIED";
  }>;
  chainState: Readonly<{
    frozen: true;
    updateAuthorityType: "None";
  }>;
  archive: Readonly<{ safety: "VERIFIED" }>;
  nativeAudit: Readonly<{ status: "PASSED" }>;
  semanticScan: Readonly<{ status: "PASSED"; signals: readonly unknown[] }>;
  trustPolicy: Readonly<{ publisher: string; trusted: true }>;
  verdict: "PASS_REQUIRES_APPROVAL";
  installEligible: true;
}>;

export class InstallError extends Error {
  readonly code: string;
  readonly receiptConsumed: boolean;

  constructor(code: string, message: string, receiptConsumed = false) {
    super(message);
    this.name = "InstallError";
    this.code = code;
    this.receiptConsumed = receiptConsumed;
  }
}

function projectRoot(): string {
  return fileURLToPath(new URL("../../", import.meta.url));
}

function defaultApprovedDirectory(): string {
  return process.env.SKILLSEAL_APPROVED_DIR || join(projectRoot(), "approved-skills");
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new InstallError("INVALID_INSPECTION_EVIDENCE", "stored inspection evidence is invalid.", true);
  }
  return value as Record<string, unknown>;
}

function parseEvidence(claim: InstallationClaim): Evidence {
  let root: Record<string, unknown>;
  try {
    root = record(JSON.parse(claim.evidenceJson));
  } catch (error: unknown) {
    if (error instanceof InstallError) throw error;
    throw new InstallError("INVALID_INSPECTION_EVIDENCE", "stored inspection evidence is invalid.", true);
  }

  const manifest = record(root.manifest);
  const payload = record(root.payload);
  const chainState = record(root.chainState);
  const archive = record(root.archive);
  const nativeAudit = record(root.nativeAudit);
  const semanticScan = record(root.semanticScan);
  const trustPolicy = record(root.trustPolicy);
  const name = manifest.name;
  const entrypoint = manifest.entrypoint;
  const permissions = manifest.permissions;
  const signals = semanticScan.signals;

  const valid =
    root.inspectionId === claim.inspectionId &&
    root.cluster === claim.cluster &&
    root.asset === claim.asset &&
    root.assetOwner === claim.publisher &&
    root.verdict === "PASS_REQUIRES_APPROVAL" &&
    root.installEligible === true &&
    payload.sha256 === claim.sha256 &&
    payload.compressedBytes === claim.compressedBytes &&
    payload.integrity === "VERIFIED" &&
    chainState.frozen === true &&
    chainState.updateAuthorityType === "None" &&
    archive.safety === "VERIFIED" &&
    nativeAudit.status === "PASSED" &&
    semanticScan.status === "PASSED" &&
    Array.isArray(signals) &&
    signals.length === 0 &&
    trustPolicy.publisher === claim.publisher &&
    trustPolicy.trusted === true &&
    typeof name === "string" &&
    SAFE_SKILL_NAME.test(name) &&
    typeof entrypoint === "string" &&
    Array.isArray(permissions) &&
    permissions.length === 0;
  if (!valid) {
    throw new InstallError(
      "INVALID_INSPECTION_EVIDENCE",
      "stored inspection evidence does not satisfy the installation contract.",
      true,
    );
  }

  return root as unknown as Evidence;
}

function assertWithin(root: string, target: string): void {
  const rootPath = resolve(root) + sep;
  const targetPath = resolve(target) + sep;
  if (!targetPath.startsWith(rootPath)) {
    throw new InstallError("UNSAFE_INSTALL_PATH", "installation target escaped the approved bundle.", true);
  }
}

async function readExactPayload(claim: InstallationClaim): Promise<Buffer> {
  try {
    const linkStatus = await lstat(claim.payloadPath);
    if (!linkStatus.isFile() || linkStatus.isSymbolicLink()) {
      throw new InstallError("INVALID_EVIDENCE_PAYLOAD", "stored inspection payload is not a regular file.", true);
    }
    const handle = await open(claim.payloadPath, "r");
    try {
      const status = await handle.stat();
      if (
        status.size !== claim.compressedBytes ||
        status.size < 0 ||
        status.size > MAX_ARCHIVE_BYTES
      ) {
        throw new InstallError(
          "EVIDENCE_PAYLOAD_MISMATCH",
          "stored inspection payload length no longer matches the approved receipt.",
          true,
        );
      }
      const payload = await handle.readFile();
      const digest = createHash("sha256").update(payload).digest("hex");
      if (payload.byteLength !== claim.compressedBytes || digest !== claim.sha256) {
        throw new InstallError(
          "EVIDENCE_PAYLOAD_MISMATCH",
          "stored inspection payload hash no longer matches the approved receipt.",
          true,
        );
      }
      return payload;
    } finally {
      await handle.close();
    }
  } catch (error: unknown) {
    if (error instanceof InstallError) throw error;
    throw new InstallError("EVIDENCE_PAYLOAD_UNAVAILABLE", "stored inspection payload is unavailable.", true);
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error: unknown) {
    if (error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

export async function installInspection(input: Readonly<{
  inspectionId: string;
  dataDirectory?: string;
  approvedDirectory?: string;
  now?: Date;
}>): Promise<InstallResult> {
  let claim: InstallationClaim;
  try {
    claim = claimInspectionForInstall(input.inspectionId, {
      ...(input.dataDirectory === undefined ? {} : { dataDirectory: input.dataDirectory }),
      ...(input.now === undefined ? {} : { now: input.now }),
    });
  } catch (error: unknown) {
    if (error instanceof InspectionStoreError) {
      throw new InstallError(error.code, error.message, error.code === "RECEIPT_CONSUMED");
    }
    throw error;
  }

  const evidence = parseEvidence(claim);
  const payload = await readExactPayload(claim);
  let scanned;
  try {
    scanned = scanTarGzip(payload, evidence.manifest.entrypoint);
  } catch (error: unknown) {
    if (error instanceof ArchiveScanError) {
      throw new InstallError(
        "ARCHIVE_REVALIDATION_FAILED",
        "stored inspection payload failed bounded archive revalidation.",
        true,
      );
    }
    throw error;
  }

  const approvedDirectory = resolve(input.approvedDirectory ?? defaultApprovedDirectory());
  await mkdir(approvedDirectory, { recursive: true, mode: 0o700 });
  const approvedStatus = await lstat(approvedDirectory);
  if (!approvedStatus.isDirectory() || approvedStatus.isSymbolicLink()) {
    throw new InstallError("UNSAFE_APPROVED_BUNDLE", "approved bundle is not a regular directory.", true);
  }
  await chmod(approvedDirectory, 0o700);

  const directoryName = `${evidence.manifest.name}-${claim.sha256.slice(0, 12)}`;
  const finalDirectory = join(approvedDirectory, directoryName);
  const lockPath = join(approvedDirectory, `.skillseal-lock-${claim.sha256}`);
  assertWithin(approvedDirectory, finalDirectory);
  assertWithin(approvedDirectory, lockPath);

  let lock;
  try {
    lock = await open(lockPath, "wx", 0o600);
  } catch (error: unknown) {
    if (error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new InstallError("INSTALL_ALREADY_IN_PROGRESS", "the same approved payload is already being installed.", true);
    }
    throw new InstallError("INSTALL_LOCK_FAILED", "failed to acquire the approved bundle lock.", true);
  }

  let stagingDirectory: string | null = null;
  let installed = false;
  try {
    if (await pathExists(finalDirectory)) {
      throw new InstallError("INSTALL_TARGET_EXISTS", "the exact approved payload is already installed.", true);
    }
    stagingDirectory = await mkdtemp(join(approvedDirectory, ".skillseal-staging-"));
    assertWithin(approvedDirectory, stagingDirectory);
    await chmod(stagingDirectory, 0o700);

    for (const entry of scanned.summary.inventory) {
      const target = join(stagingDirectory, entry.path);
      assertWithin(stagingDirectory, target);
      if (entry.type === "directory") {
        await mkdir(target, { recursive: true, mode: 0o700 });
        await chmod(target, 0o700);
        continue;
      }
      await mkdir(dirname(target), { recursive: true, mode: 0o700 });
      const bytes = scanned.files.get(entry.path);
      if (bytes === undefined) {
        throw new InstallError("ARCHIVE_REVALIDATION_FAILED", "archive inventory is internally inconsistent.", true);
      }
      await writeFile(target, bytes, { flag: "wx", mode: 0o600 });
    }

    await rename(stagingDirectory, finalDirectory);
    stagingDirectory = null;
    installed = true;
  } catch (error: unknown) {
    if (error instanceof InstallError) throw error;
    throw new InstallError("ATOMIC_INSTALL_FAILED", "failed to atomically install the approved payload.", true);
  } finally {
    if (stagingDirectory !== null) await rm(stagingDirectory, { recursive: true, force: true });
    await lock.close();
    await unlink(lockPath).catch(() => undefined);
  }

  if (!installed) {
    throw new InstallError("ATOMIC_INSTALL_FAILED", "approved payload was not installed.", true);
  }
  return {
    service: "skillseal",
    version: "0.1.0",
    status: "installed",
    custody: "T0_READ",
    localEffect: "HUMAN_APPROVED_SKILL_BUNDLE_WRITE",
    verdict: "INSTALLED_PINNED",
    inspectionId: claim.inspectionId,
    receiptState: "CONSUMED",
    consumedAt: claim.consumedAt,
    cluster: claim.cluster,
    asset: claim.asset,
    sha256: claim.sha256,
    frozen: true,
    publisher: claim.publisher,
    bundle: "skillseal_approved",
    directoryName,
    entrypoint: evidence.manifest.entrypoint,
    filesInstalled: scanned.summary.files,
    payloadExecuted: false,
    requiresNewSession: true,
  };
}
