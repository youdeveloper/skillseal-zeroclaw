import { createHash } from "node:crypto";

import { deserializeAssetV1, type AssetV1 } from "@metaplex-foundation/mpl-core";
import { publicKey } from "@metaplex-foundation/umi";

import { ArchiveScanError, scanTarGzip } from "../archive/scan.js";
import { NativeAuditError, runZeroClawNativeAudit } from "../audit/zeroclaw.js";
import type {
  ArchiveInspectResult,
  ChainMetadataInspectResult,
  InspectCluster,
  InspectFinding,
  InspectResult,
  NativeAuditInspectResult,
  PolicyInspectResult,
} from "../domain/verdict.js";
import { scanSemanticPolicy } from "../policy/semantic.js";
import { evaluateTrustPolicy, TrustPolicyError } from "../policy/trust.js";
import {
  InspectionStoreError,
  newInspectionId,
  persistInspection,
} from "../store/inspections.js";

export const MPL_CORE_PROGRAM_ID = "CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d";
export const GITLANA_STANDARD = "onchain-skill/0.1";

const MAX_ARCHIVE_BYTES = 1_048_576;
const MAX_RPC_RESPONSE_BYTES = 2_000_000;
const RPC_TIMEOUT_MS = 15_000;

const DEFAULT_RPC: Readonly<Record<InspectCluster, string>> = {
  devnet: "https://api.devnet.solana.com",
  "mainnet-beta": "https://api.mainnet-beta.solana.com",
};

const RPC_ENV: Readonly<Record<InspectCluster, string>> = {
  devnet: "SKILLSEAL_RPC_DEVNET",
  "mainnet-beta": "SKILLSEAL_RPC_MAINNET_BETA",
};

type FetchLike = typeof fetch;

export class InspectError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "InspectError";
    this.code = code;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireRecord(value: unknown, code: string, message: string): Record<string, unknown> {
  if (!isRecord(value)) throw new InspectError(code, message);
  return value;
}

function requireString(value: unknown, code: string, message: string): string {
  if (typeof value !== "string") throw new InspectError(code, message);
  return value;
}

function requireNumber(value: unknown, code: string, message: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new InspectError(code, message);
  }
  return value;
}

function validatePublicKey(value: string, field: string): string {
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) {
    throw new InspectError("INVALID_PUBLIC_KEY", `${field} is not a valid Solana public key.`);
  }
  try {
    publicKey(value);
  } catch {
    throw new InspectError("INVALID_PUBLIC_KEY", `${field} is not a valid 32-byte Solana public key.`);
  }
  return value;
}

function optionalPublicKey(value: string | undefined, field: string): string | null {
  if (value === undefined || value === "") return null;
  return validatePublicKey(value, field);
}

function validateEntrypoint(value: string): string {
  if (value.length === 0 || Buffer.byteLength(value, "utf8") > 240) {
    throw new InspectError("INVALID_ENTRYPOINT", "entrypoint is empty or exceeds 240 UTF-8 bytes.");
  }
  if (value.startsWith("/") || value.includes("\\") || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new InspectError("INVALID_ENTRYPOINT", "entrypoint is not a safe portable relative path.");
  }
  const segments = value.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new InspectError("INVALID_ENTRYPOINT", "entrypoint contains an unsafe path segment.");
  }
  return value;
}

function parsePermissions(value: string): readonly string[] {
  if (value === "") return [];
  const permissions = value.split(",").map((item) => item.trim());
  if (
    permissions.some(
      (item) =>
        item.length === 0 ||
        Buffer.byteLength(item, "utf8") > 128 ||
        /[\u0000-\u001f\u007f]/.test(item),
    )
  ) {
    throw new InspectError("INVALID_PERMISSIONS", "permissions contains an empty, oversized, or control-character value.");
  }
  if (new Set(permissions).size !== permissions.length) {
    throw new InspectError("DUPLICATE_PERMISSION", "permissions contains duplicate values.");
  }
  return permissions;
}

function attributesToRecord(
  attributeList: readonly Readonly<{ key: string; value: string }>[],
): Readonly<Record<string, string>> {
  const attributes: Record<string, string> = {};
  for (const attribute of attributeList) {
    if (attribute.key.length === 0 || Object.hasOwn(attributes, attribute.key)) {
      throw new InspectError("AMBIGUOUS_ATTRIBUTES", "manifest contains an empty or duplicate attribute key.");
    }
    attributes[attribute.key] = attribute.value;
  }
  return attributes;
}

function requiredAttribute(attributes: Readonly<Record<string, string>>, key: string): string {
  const value = attributes[key];
  if (value === undefined) {
    throw new InspectError("MISSING_ATTRIBUTE", `manifest is missing required attribute '${key}'.`);
  }
  return value;
}

function parseContentLength(value: string): number {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new InspectError("INVALID_CONTENT_LENGTH", "content_length must be a canonical non-negative integer.");
  }
  const length = Number(value);
  if (!Number.isSafeInteger(length) || length > MAX_ARCHIVE_BYTES) {
    throw new InspectError("ARCHIVE_TOO_LARGE", `compressed payload exceeds the ${MAX_ARCHIVE_BYTES}-byte policy limit.`);
  }
  return length;
}

function parseContentSha256(value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new InspectError("INVALID_CONTENT_SHA256", "content_sha256 must be 64 lowercase hexadecimal characters.");
  }
  return value;
}

function payloadBytes(asset: AssetV1): Uint8Array {
  const candidates = (asset.appDatas ?? []).filter(
    (item) => item.dataAuthority.type === "UpdateAuthority",
  );
  if (candidates.length !== 1) {
    throw new InspectError(
      "AMBIGUOUS_APP_DATA",
      "asset must contain exactly one AppData payload controlled by UpdateAuthority.",
    );
  }
  const data: unknown = candidates[0]?.data;
  if (!(data instanceof Uint8Array)) {
    throw new InspectError("MISSING_PAYLOAD", "asset AppData does not contain a binary payload.");
  }
  return data;
}

function updateAuthority(asset: AssetV1): {
  type: "None" | "Address" | "Collection";
  address: string | null;
} {
  const type = asset.updateAuthority.type;
  if (type === "None") return { type, address: null };
  if (type !== "Address" && type !== "Collection") {
    throw new InspectError("INVALID_UPDATE_AUTHORITY", "asset has an unsupported update-authority type.");
  }
  if (asset.updateAuthority.address === undefined) {
    throw new InspectError("INVALID_UPDATE_AUTHORITY", "mutable asset is missing its update-authority address.");
  }
  return {
    type,
    address: validatePublicKey(String(asset.updateAuthority.address), "update authority"),
  };
}

export function assessDecodedGitlanaAsset(input: Readonly<{
  cluster: InspectCluster;
  assetAddress: string;
  slot: number;
  decoded: AssetV1;
}>): ChainMetadataInspectResult {
  const { cluster, slot, decoded } = input;
  const assetAddress = validatePublicKey(input.assetAddress, "asset");

  if (decoded.header.executable) {
    throw new InspectError("EXECUTABLE_ACCOUNT", "asset account is unexpectedly executable.");
  }
  const programOwner = String(decoded.header.owner);
  if (programOwner !== MPL_CORE_PROGRAM_ID) {
    throw new InspectError("WRONG_PROGRAM_OWNER", "asset account is not owned by the Metaplex Core program.");
  }
  if (decoded.attributes?.authority.type !== "UpdateAuthority") {
    throw new InspectError("INVALID_ATTRIBUTES_AUTHORITY", "Attributes plugin is not controlled by UpdateAuthority.");
  }

  const attributes = attributesToRecord(decoded.attributes.attributeList);
  if (requiredAttribute(attributes, "standard") !== GITLANA_STANDARD) {
    throw new InspectError("UNSUPPORTED_STANDARD", `asset is not ${GITLANA_STANDARD}.`);
  }
  if (requiredAttribute(attributes, "encoding") !== "tar+gzip") {
    throw new InspectError("UNSUPPORTED_ENCODING", "asset payload encoding is not tar+gzip.");
  }

  const bytes = payloadBytes(decoded);
  const declaredLength = parseContentLength(requiredAttribute(attributes, "content_length"));
  if (bytes.byteLength !== declaredLength) {
    throw new InspectError(
      "LENGTH_MISMATCH",
      `payload length mismatch: manifest=${declaredLength}, actual=${bytes.byteLength}.`,
    );
  }

  const declaredHash = parseContentSha256(requiredAttribute(attributes, "content_sha256"));
  const actualHash = createHash("sha256").update(bytes).digest("hex");
  if (actualHash !== declaredHash) {
    throw new InspectError(
      "HASH_MISMATCH",
      `payload SHA-256 mismatch: manifest=${declaredHash}, actual=${actualHash}.`,
    );
  }

  const authority = updateAuthority(decoded);
  const frozen = authority.type === "None";
  const findings: InspectFinding[] = [
    {
      code: "CHAIN_METADATA_VERIFIED",
      severity: "INFO",
      message: "Metaplex owner, Gitlana manifest, payload length, and SHA-256 were verified at a finalized slot.",
    },
    frozen
      ? {
          code: "FROZEN_SNAPSHOT",
          severity: "INFO",
          message: "Update authority is revoked; this asset is an immutable snapshot.",
        }
      : {
          code: "MUTABLE_ASSET",
          severity: "HIGH",
          message: "Update authority is active; the same asset address can serve different bytes later.",
        },
    {
      code: "TRUST_POLICY_PENDING",
      severity: "HIGH",
      message: "Publisher identity has not yet been matched against the local trusted-authority policy.",
    },
    {
      code: "ARCHIVE_SCAN_PENDING",
      severity: "HIGH",
      message: "The tar archive has not yet passed path, link, file-count, and expansion-limit checks.",
    },
    {
      code: "ZEROCLAW_AUDIT_PENDING",
      severity: "HIGH",
      message: "ZeroClaw native skill audit and SkillSeal semantic policy scan have not yet run.",
    },
  ];

  return {
    service: "skillseal",
    version: "0.1.0",
    status: "review_blocked",
    scope: "CHAIN_METADATA_ONLY",
    custody: "T0_READ",
    inspectionId: null,
    cluster,
    asset: assetAddress,
    slot,
    programOwner,
    assetOwner: validatePublicKey(String(decoded.owner), "asset owner"),
    manifest: {
      standard: GITLANA_STANDARD,
      name: requiredAttribute(attributes, "name"),
      version: requiredAttribute(attributes, "version"),
      license: requiredAttribute(attributes, "license"),
      encoding: "tar+gzip",
      entrypoint: validateEntrypoint(requiredAttribute(attributes, "entrypoint")),
      permissions: parsePermissions(requiredAttribute(attributes, "permissions")),
    },
    payload: {
      compressedBytes: declaredLength,
      sha256: actualHash,
      integrity: "VERIFIED",
    },
    chainState: {
      frozen,
      updateAuthorityType: authority.type,
      updateAuthority: authority.address,
      repoHead: optionalPublicKey(attributes.head, "repo head"),
      snapshotOf: optionalPublicKey(attributes.snapshot_of, "snapshot_of"),
      parentSnapshot: optionalPublicKey(attributes.parent, "parent snapshot"),
    },
    verdict: "REVIEW_BLOCKED",
    installEligible: false,
    findings,
  };
}

async function readLimitedText(response: Response): Promise<string> {
  const headerLength = response.headers.get("content-length");
  if (headerLength !== null && Number(headerLength) > MAX_RPC_RESPONSE_BYTES) {
    throw new InspectError("RPC_RESPONSE_TOO_LARGE", "RPC response exceeds the local size limit.");
  }
  if (response.body === null) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RPC_RESPONSE_BYTES) {
      await reader.cancel();
      throw new InspectError("RPC_RESPONSE_TOO_LARGE", "RPC response exceeds the local size limit.");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks, total).toString("utf8");
}

function parseRpcAccount(payload: unknown, assetAddress: string): { slot: number; decoded: AssetV1 } {
  const root = requireRecord(payload, "INVALID_RPC_RESPONSE", "RPC response is not a JSON object.");
  if (root.error !== undefined) {
    const error = requireRecord(root.error, "RPC_ERROR", "RPC returned an unreadable error.");
    const code = typeof error.code === "number" ? String(error.code) : "unknown";
    throw new InspectError("RPC_ERROR", `Solana RPC rejected getAccountInfo (code ${code}).`);
  }
  const result = requireRecord(root.result, "INVALID_RPC_RESPONSE", "RPC response is missing result.");
  const context = requireRecord(result.context, "INVALID_RPC_RESPONSE", "RPC response is missing context.");
  const slot = requireNumber(context.slot, "INVALID_RPC_RESPONSE", "RPC context slot is invalid.");
  const value = requireRecord(result.value, "ACCOUNT_NOT_FOUND", "asset account does not exist at the finalized slot.");
  const owner = requireString(value.owner, "INVALID_RPC_RESPONSE", "RPC account owner is invalid.");
  if (owner !== MPL_CORE_PROGRAM_ID) {
    throw new InspectError("WRONG_PROGRAM_OWNER", "asset account is not owned by the Metaplex Core program.");
  }
  if (value.executable !== false) {
    throw new InspectError("EXECUTABLE_ACCOUNT", "asset account is unexpectedly executable.");
  }
  const lamports = requireNumber(value.lamports, "INVALID_RPC_RESPONSE", "RPC lamports value is invalid.");
  if (!Array.isArray(value.data) || value.data.length !== 2 || value.data[1] !== "base64") {
    throw new InspectError("INVALID_RPC_RESPONSE", "RPC account data is not base64 encoded.");
  }
  const encoded = requireString(value.data[0], "INVALID_RPC_RESPONSE", "RPC account data is invalid.");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    throw new InspectError("INVALID_BASE64", "RPC account data contains invalid base64.");
  }
  const data = Buffer.from(encoded, "base64");

  try {
    const decoded = deserializeAssetV1({
      publicKey: publicKey(assetAddress),
      executable: false,
      owner: publicKey(owner),
      lamports: { basisPoints: BigInt(lamports), identifier: "SOL", decimals: 9 },
      data,
    });
    return { slot, decoded };
  } catch {
    throw new InspectError("MPL_CORE_DECODE_FAILED", "Metaplex Core asset decoding failed.");
  }
}

export async function inspectGitlanaAsset(input: Readonly<{
  cluster: InspectCluster;
  asset: string;
  fetchImpl?: FetchLike;
}>): Promise<InspectResult> {
  const { cluster } = input;
  if (cluster !== "devnet" && cluster !== "mainnet-beta") {
    throw new InspectError("CLUSTER_NOT_ALLOWED", "cluster is not allowed by the local policy.");
  }
  const assetAddress = validatePublicKey(input.asset, "asset");
  const endpoint = process.env[RPC_ENV[cluster]] || DEFAULT_RPC[cluster];
  const fetchImpl = input.fetchImpl ?? fetch;

  let response: Response;
  try {
    response = await fetchImpl(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "skillseal-inspect",
        method: "getAccountInfo",
        params: [assetAddress, { encoding: "base64", commitment: "finalized" }],
      }),
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    });
  } catch {
    throw new InspectError("RPC_UNAVAILABLE", "Solana RPC request failed or timed out.");
  }
  if (!response.ok) {
    throw new InspectError("RPC_HTTP_ERROR", `Solana RPC returned HTTP ${response.status}.`);
  }

  const text = await readLimitedText(response);
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new InspectError("INVALID_RPC_JSON", "Solana RPC returned invalid JSON.");
  }
  const { slot, decoded } = parseRpcAccount(payload, assetAddress);
  const metadata = assessDecodedGitlanaAsset({ cluster, assetAddress, slot, decoded });
  let archive;
  try {
    archive = scanTarGzip(payloadBytes(decoded), metadata.manifest.entrypoint);
  } catch (error: unknown) {
    if (error instanceof ArchiveScanError) throw new InspectError(error.code, error.message);
    throw error;
  }
  const findings: InspectFinding[] = [
    ...metadata.findings.filter((finding) => finding.code !== "ARCHIVE_SCAN_PENDING"),
    {
      code: "ARCHIVE_PREFLIGHT_VERIFIED",
      severity: "INFO",
      message: "The gzip and ustar structure, checksums, paths, entry types, limits, and declared entrypoint passed preflight.",
    },
  ];

  const archiveResult: ArchiveInspectResult = {
    ...metadata,
    scope: "ARCHIVE_PREFLIGHT",
    archive: archive.summary,
    findings,
  };

  let nativeAudit;
  try {
    nativeAudit = await runZeroClawNativeAudit(archive);
  } catch (error: unknown) {
    if (error instanceof NativeAuditError) throw new InspectError(error.code, error.message);
    throw error;
  }
  const nativeResult: NativeAuditInspectResult = {
    ...archiveResult,
    scope: "NATIVE_AUDIT",
    nativeAudit,
    findings: [
      ...archiveResult.findings.filter((finding) => finding.code !== "ZEROCLAW_AUDIT_PENDING"),
      {
        code: "ZEROCLAW_NATIVE_AUDIT_VERIFIED",
        severity: "INFO",
        message: "The exact quarantined bytes passed ZeroClaw's native skill audit.",
      },
      {
        code: "SEMANTIC_SCAN_PENDING",
        severity: "HIGH",
        message: "SkillSeal semantic policy scanning has not yet evaluated the entrypoint and scripts.",
      },
    ],
  };

  const semanticScan = scanSemanticPolicy({
    files: archive.files,
    declaredPermissions: nativeResult.manifest.permissions,
    allowScripts: false,
  });
  const denied = semanticScan.verdictImpact === "DENY";
  const policyResult: PolicyInspectResult = {
    ...nativeResult,
    status: denied ? "denied" : "review_blocked",
    scope: "SEMANTIC_POLICY",
    semanticScan: {
      status: semanticScan.status,
      filesScanned: semanticScan.filesScanned,
      textFiles: semanticScan.textFiles,
      binaryFiles: semanticScan.binaryFiles,
      signals: semanticScan.signals,
    },
    verdict: denied ? "DENY" : "REVIEW_BLOCKED",
    findings: [
      ...nativeResult.findings.filter((finding) => finding.code !== "SEMANTIC_SCAN_PENDING"),
      {
        code: "SEMANTIC_POLICY_COMPLETED",
        severity: "INFO",
        message: "SkillSeal completed deterministic text, permission, script, binary, and obfuscation policy checks.",
      },
      ...semanticScan.signals.map((item) => ({
        code: item.code,
        severity: "HIGH" as const,
        message: item.message,
      })),
    ],
  };

  let trustPolicy;
  try {
    trustPolicy = evaluateTrustPolicy(policyResult.assetOwner);
  } catch (error: unknown) {
    if (error instanceof TrustPolicyError) throw new InspectError(error.code, error.message);
    throw error;
  }
  const pass =
    !denied &&
    policyResult.semanticScan.status === "PASSED" &&
    policyResult.chainState.frozen &&
    trustPolicy.trusted;
  const verdict = denied ? "DENY" : pass ? "PASS_REQUIRES_APPROVAL" : "REVIEW_BLOCKED";
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.parse(createdAt) + 600_000).toISOString();
  const inspectionId = newInspectionId(createdAt);
  const finalResult: InspectResult = {
    ...policyResult,
    status: denied ? "denied" : pass ? "pass_requires_approval" : "review_blocked",
    scope: "PERSISTED_VERDICT",
    inspectionId,
    createdAt,
    expiresAt,
    trustPolicy,
    verdict,
    installEligible: pass,
    findings: [
      ...policyResult.findings.filter((finding) => finding.code !== "TRUST_POLICY_PENDING"),
      trustPolicy.trusted
        ? {
            code: "TRUSTED_AUTHORITY_VERIFIED",
            severity: "INFO",
            message: "Asset owner matches the local trusted-authority allowlist.",
          }
        : {
            code: "UNTRUSTED_AUTHORITY",
            severity: "HIGH",
            message: "Asset owner is not present in the local trusted-authority allowlist.",
          },
      {
        code: "INSPECTION_EVIDENCE_PERSISTED",
        severity: "INFO",
        message: "Exact compressed bytes and the structured verdict were persisted under the inspection id.",
      },
    ],
  };

  try {
    await persistInspection({ result: finalResult, compressedPayload: payloadBytes(decoded) });
  } catch (error: unknown) {
    if (error instanceof InspectionStoreError) throw new InspectError(error.code, error.message);
    throw error;
  }
  return finalResult;
}
