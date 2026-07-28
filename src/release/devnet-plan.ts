export const OFFICIAL_DEVNET_RPC = "https://api.devnet.solana.com";
const STANDARD = "onchain-skill/0.1";
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

export class DevnetReleasePlanError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "DevnetReleasePlanError";
    this.code = code;
  }
}

export type DevnetReleaseConfig = Readonly<{
  cluster: string;
  rpc: string;
  repoAsset: string;
  publisher: string;
  expectedCurrentName: string;
  expectedCurrentVersion: string;
  expectedCurrentLicense: string;
  expectedCurrentEntrypoint: string;
  expectedCurrentSha256: string;
  expectedCurrentHead: string;
  expectedParentSha256: string;
  candidateDirectory: string;
  candidateName: string;
  candidateVersion: string;
  candidateLicense: string;
  candidateEntrypoint: string;
  candidateSha256: string;
}>;

export type ReleaseCandidate = Readonly<{
  name: string;
  version: string;
  license: string;
  entrypoint: string;
  permissions: readonly string[];
  compressedBytes: number;
  sha256: string;
}>;

export type ChainSkillState = Readonly<{
  cluster: string;
  asset: string;
  owner: string;
  frozen: boolean;
  updateAuthority: string | null;
  standard: string;
  name: string;
  version: string;
  license: string;
  entrypoint: string;
  permissions: string;
  sha256: string;
  head: string | null;
  snapshotOf: string | null;
  parent: string | null;
}>;

function fail(code: string, message: string): never {
  throw new DevnetReleasePlanError(code, message);
}

function requireEqual(actual: unknown, expected: unknown, code: string, field: string): void {
  if (actual !== expected) fail(code, `${field} does not match the pinned release plan.`);
}

function validateConfig(config: DevnetReleaseConfig): void {
  requireEqual(config.cluster, "devnet", "CLUSTER_FORBIDDEN", "cluster");
  requireEqual(config.rpc, OFFICIAL_DEVNET_RPC, "RPC_FORBIDDEN", "rpc");
  if (config.repoAsset === config.expectedCurrentHead) {
    fail("INVALID_RELEASE_LINEAGE", "repo Asset and parent snapshot must be different.");
  }
  for (const [field, value] of [
    ["expectedCurrentSha256", config.expectedCurrentSha256],
    ["expectedParentSha256", config.expectedParentSha256],
    ["candidateSha256", config.candidateSha256],
  ] as const) {
    if (!SHA256_PATTERN.test(value)) fail("INVALID_PINNED_SHA256", `${field} is not a SHA-256 value.`);
  }
}

function validateCandidate(config: DevnetReleaseConfig, candidate: ReleaseCandidate): void {
  requireEqual(candidate.name, config.candidateName, "CANDIDATE_MISMATCH", "candidate name");
  requireEqual(candidate.version, config.candidateVersion, "CANDIDATE_MISMATCH", "candidate version");
  requireEqual(candidate.license, config.candidateLicense, "CANDIDATE_MISMATCH", "candidate license");
  requireEqual(
    candidate.entrypoint,
    config.candidateEntrypoint,
    "CANDIDATE_MISMATCH",
    "candidate entrypoint",
  );
  requireEqual(candidate.sha256, config.candidateSha256, "CANDIDATE_MISMATCH", "candidate SHA-256");
  if (!Number.isSafeInteger(candidate.compressedBytes) || candidate.compressedBytes <= 0) {
    fail("CANDIDATE_MISMATCH", "candidate compressed size is invalid.");
  }
  if (candidate.permissions.length !== 0) {
    fail("CANDIDATE_PERMISSIONS_FORBIDDEN", "release candidate permissions must remain empty.");
  }
}

export function lineagePreservingManifest(
  config: DevnetReleaseConfig,
  candidate: ReleaseCandidate,
): Readonly<{
  name: string;
  version: string;
  license: string;
  entrypoint: string;
  permissions: readonly string[];
  extra: readonly Readonly<{ key: "head"; value: string }>[];
}> {
  validateConfig(config);
  validateCandidate(config, candidate);
  return {
    name: candidate.name,
    version: candidate.version,
    license: candidate.license,
    entrypoint: candidate.entrypoint,
    permissions: candidate.permissions,
    extra: [{ key: "head", value: config.expectedCurrentHead }],
  };
}

export function buildOfflineReleasePlan(
  config: DevnetReleaseConfig,
  candidate: ReleaseCandidate,
): Readonly<Record<string, unknown>> {
  const manifest = lineagePreservingManifest(config, candidate);
  return {
    service: "skillseal-devnet-release",
    version: "0.1.0",
    status: "DRY_RUN_READY",
    cluster: "devnet",
    rpc: OFFICIAL_DEVNET_RPC,
    repoAsset: config.repoAsset,
    publisher: config.publisher,
    expectedParentSnapshot: config.expectedCurrentHead,
    candidate: {
      name: candidate.name,
      version: candidate.version,
      compressedBytes: candidate.compressedBytes,
      sha256: candidate.sha256,
      permissions: candidate.permissions,
    },
    preservedAttributes: manifest.extra,
    executionInterlocks: [
      "--execute",
      "--confirm-repo",
      "--confirm-parent",
      "--confirm-sha",
      "SKILLSEAL_DEVNET_KEYPAIR",
    ],
    steps: [
      "read and validate the live mutable Repo",
      "read and validate the frozen parent snapshot",
      "load the devnet-only signer after read-only preflight",
      "update Repo payload and manifest while preserving the old head",
      "read back and verify exact candidate bytes and preserved head",
      "mint and freeze a child snapshot from verified on-chain bytes",
      "verify child parent, Repo head, frozen state, and pinned SHA-256",
    ],
    networkAccessed: false,
    keypairRead: false,
    chainWrites: 0,
  };
}

export function assertExecutionConfirmations(
  config: DevnetReleaseConfig,
  candidate: ReleaseCandidate,
  confirmations: Readonly<{
    repo?: string;
    parent?: string;
    sha256?: string;
  }>,
): void {
  validateConfig(config);
  validateCandidate(config, candidate);
  requireEqual(confirmations.repo, config.repoAsset, "EXECUTION_CONFIRMATION_MISMATCH", "confirmed Repo");
  requireEqual(
    confirmations.parent,
    config.expectedCurrentHead,
    "EXECUTION_CONFIRMATION_MISMATCH",
    "confirmed parent",
  );
  requireEqual(
    confirmations.sha256,
    config.candidateSha256,
    "EXECUTION_CONFIRMATION_MISMATCH",
    "confirmed SHA-256",
  );
}

export function assertLivePreconditions(
  config: DevnetReleaseConfig,
  repo: ChainSkillState,
  parent: ChainSkillState,
): void {
  validateConfig(config);
  requireEqual(repo.cluster, "devnet", "LIVE_REPO_MISMATCH", "Repo cluster");
  requireEqual(repo.asset, config.repoAsset, "LIVE_REPO_MISMATCH", "Repo Asset");
  requireEqual(repo.owner, config.publisher, "LIVE_REPO_MISMATCH", "Repo owner");
  requireEqual(repo.frozen, false, "LIVE_REPO_MISMATCH", "Repo frozen state");
  requireEqual(repo.updateAuthority, config.publisher, "LIVE_REPO_MISMATCH", "Repo update authority");
  requireEqual(repo.standard, STANDARD, "LIVE_REPO_MISMATCH", "Repo standard");
  requireEqual(repo.name, config.expectedCurrentName, "LIVE_REPO_MISMATCH", "Repo name");
  requireEqual(repo.version, config.expectedCurrentVersion, "LIVE_REPO_MISMATCH", "Repo version");
  requireEqual(repo.license, config.expectedCurrentLicense, "LIVE_REPO_MISMATCH", "Repo license");
  requireEqual(
    repo.entrypoint,
    config.expectedCurrentEntrypoint,
    "LIVE_REPO_MISMATCH",
    "Repo entrypoint",
  );
  requireEqual(repo.permissions, "", "LIVE_REPO_MISMATCH", "Repo permissions");
  requireEqual(repo.sha256, config.expectedCurrentSha256, "LIVE_REPO_MISMATCH", "Repo SHA-256");
  requireEqual(repo.head, config.expectedCurrentHead, "LIVE_REPO_MISMATCH", "Repo head");

  requireEqual(parent.cluster, "devnet", "LIVE_PARENT_MISMATCH", "parent cluster");
  requireEqual(parent.asset, config.expectedCurrentHead, "LIVE_PARENT_MISMATCH", "parent Asset");
  requireEqual(parent.owner, config.publisher, "LIVE_PARENT_MISMATCH", "parent owner");
  requireEqual(parent.frozen, true, "LIVE_PARENT_MISMATCH", "parent frozen state");
  requireEqual(parent.updateAuthority, null, "LIVE_PARENT_MISMATCH", "parent update authority");
  requireEqual(parent.standard, STANDARD, "LIVE_PARENT_MISMATCH", "parent standard");
  requireEqual(parent.license, config.expectedCurrentLicense, "LIVE_PARENT_MISMATCH", "parent license");
  requireEqual(
    parent.entrypoint,
    config.expectedCurrentEntrypoint,
    "LIVE_PARENT_MISMATCH",
    "parent entrypoint",
  );
  requireEqual(parent.permissions, "", "LIVE_PARENT_MISMATCH", "parent permissions");
  requireEqual(parent.sha256, config.expectedParentSha256, "LIVE_PARENT_MISMATCH", "parent SHA-256");
  requireEqual(parent.snapshotOf, config.repoAsset, "LIVE_PARENT_MISMATCH", "parent snapshot_of");
}

export function assertUpdatedRepo(
  config: DevnetReleaseConfig,
  candidate: ReleaseCandidate,
  repo: ChainSkillState,
): void {
  validateConfig(config);
  validateCandidate(config, candidate);
  requireEqual(repo.cluster, "devnet", "UPDATED_REPO_MISMATCH", "updated Repo cluster");
  requireEqual(repo.asset, config.repoAsset, "UPDATED_REPO_MISMATCH", "updated Repo Asset");
  requireEqual(repo.owner, config.publisher, "UPDATED_REPO_MISMATCH", "updated Repo owner");
  requireEqual(repo.frozen, false, "UPDATED_REPO_MISMATCH", "updated Repo frozen state");
  requireEqual(repo.updateAuthority, config.publisher, "UPDATED_REPO_MISMATCH", "updated Repo authority");
  requireEqual(repo.standard, STANDARD, "UPDATED_REPO_MISMATCH", "updated Repo standard");
  requireEqual(repo.name, candidate.name, "UPDATED_REPO_MISMATCH", "updated Repo name");
  requireEqual(repo.version, candidate.version, "UPDATED_REPO_MISMATCH", "updated Repo version");
  requireEqual(repo.license, candidate.license, "UPDATED_REPO_MISMATCH", "updated Repo license");
  requireEqual(repo.entrypoint, candidate.entrypoint, "UPDATED_REPO_MISMATCH", "updated Repo entrypoint");
  requireEqual(repo.permissions, "", "UPDATED_REPO_MISMATCH", "updated Repo permissions");
  requireEqual(repo.sha256, candidate.sha256, "UPDATED_REPO_MISMATCH", "updated Repo SHA-256");
  requireEqual(repo.head, config.expectedCurrentHead, "UPDATED_REPO_MISMATCH", "preserved Repo head");
}

export function assertReleasedState(
  config: DevnetReleaseConfig,
  candidate: ReleaseCandidate,
  newSnapshot: ChainSkillState,
  repoAfterRelease: ChainSkillState,
): void {
  validateConfig(config);
  validateCandidate(config, candidate);
  if (newSnapshot.asset === config.repoAsset || newSnapshot.asset === config.expectedCurrentHead) {
    fail("RELEASED_SNAPSHOT_MISMATCH", "new snapshot must use a distinct Asset address.");
  }
  requireEqual(newSnapshot.cluster, "devnet", "RELEASED_SNAPSHOT_MISMATCH", "snapshot cluster");
  requireEqual(newSnapshot.owner, config.publisher, "RELEASED_SNAPSHOT_MISMATCH", "snapshot owner");
  requireEqual(newSnapshot.frozen, true, "RELEASED_SNAPSHOT_MISMATCH", "snapshot frozen state");
  requireEqual(newSnapshot.updateAuthority, null, "RELEASED_SNAPSHOT_MISMATCH", "snapshot authority");
  requireEqual(newSnapshot.standard, STANDARD, "RELEASED_SNAPSHOT_MISMATCH", "snapshot standard");
  requireEqual(newSnapshot.name, candidate.name, "RELEASED_SNAPSHOT_MISMATCH", "snapshot name");
  requireEqual(newSnapshot.version, candidate.version, "RELEASED_SNAPSHOT_MISMATCH", "snapshot version");
  requireEqual(newSnapshot.license, candidate.license, "RELEASED_SNAPSHOT_MISMATCH", "snapshot license");
  requireEqual(
    newSnapshot.entrypoint,
    candidate.entrypoint,
    "RELEASED_SNAPSHOT_MISMATCH",
    "snapshot entrypoint",
  );
  requireEqual(newSnapshot.permissions, "", "RELEASED_SNAPSHOT_MISMATCH", "snapshot permissions");
  requireEqual(newSnapshot.sha256, candidate.sha256, "RELEASED_SNAPSHOT_MISMATCH", "snapshot SHA-256");
  requireEqual(newSnapshot.snapshotOf, config.repoAsset, "RELEASED_SNAPSHOT_MISMATCH", "snapshot_of");
  requireEqual(newSnapshot.parent, config.expectedCurrentHead, "RELEASED_SNAPSHOT_MISMATCH", "snapshot parent");
  requireEqual(repoAfterRelease.cluster, "devnet", "RELEASED_SNAPSHOT_MISMATCH", "Repo cluster");
  requireEqual(repoAfterRelease.asset, config.repoAsset, "RELEASED_SNAPSHOT_MISMATCH", "Repo Asset");
  requireEqual(repoAfterRelease.owner, config.publisher, "RELEASED_SNAPSHOT_MISMATCH", "Repo owner");
  requireEqual(repoAfterRelease.frozen, false, "RELEASED_SNAPSHOT_MISMATCH", "Repo frozen state");
  requireEqual(
    repoAfterRelease.updateAuthority,
    config.publisher,
    "RELEASED_SNAPSHOT_MISMATCH",
    "Repo authority",
  );
  requireEqual(repoAfterRelease.name, candidate.name, "RELEASED_SNAPSHOT_MISMATCH", "Repo name");
  requireEqual(repoAfterRelease.version, candidate.version, "RELEASED_SNAPSHOT_MISMATCH", "Repo version");
  requireEqual(repoAfterRelease.license, candidate.license, "RELEASED_SNAPSHOT_MISMATCH", "Repo license");
  requireEqual(repoAfterRelease.entrypoint, candidate.entrypoint, "RELEASED_SNAPSHOT_MISMATCH", "Repo entrypoint");
  requireEqual(repoAfterRelease.permissions, "", "RELEASED_SNAPSHOT_MISMATCH", "Repo permissions");
  requireEqual(repoAfterRelease.head, newSnapshot.asset, "RELEASED_SNAPSHOT_MISMATCH", "new Repo head");
  requireEqual(repoAfterRelease.sha256, candidate.sha256, "RELEASED_SNAPSHOT_MISMATCH", "Repo SHA-256");
}
