export const verdicts = [
  "DENY",
  "REVIEW_BLOCKED",
  "PASS_REQUIRES_APPROVAL",
  "INSTALLED_PINNED",
] as const;

export type Verdict = (typeof verdicts)[number];

export type ProbeResult = Readonly<{
  service: "skillseal";
  version: string;
  status: "ok";
  custody: "T0_READ";
  installMode: "HUMAN_APPROVAL_REQUIRED";
  nonce: string;
}>;

export type InspectCluster = "devnet" | "mainnet-beta";

export type InspectFinding = Readonly<{
  code: string;
  severity: "INFO" | "MEDIUM" | "HIGH";
  message: string;
}>;

export type ChainMetadataInspectResult = Readonly<{
  service: "skillseal";
  version: string;
  status: "review_blocked";
  scope: "CHAIN_METADATA_ONLY";
  custody: "T0_READ";
  inspectionId: null;
  cluster: InspectCluster;
  asset: string;
  slot: number;
  programOwner: string;
  assetOwner: string;
  manifest: Readonly<{
    standard: "onchain-skill/0.1";
    name: string;
    version: string;
    license: string;
    encoding: "tar+gzip";
    entrypoint: string;
    permissions: readonly string[];
  }>;
  payload: Readonly<{
    compressedBytes: number;
    sha256: string;
    integrity: "VERIFIED";
  }>;
  chainState: Readonly<{
    frozen: boolean;
    updateAuthorityType: "None" | "Address" | "Collection";
    updateAuthority: string | null;
    repoHead: string | null;
    snapshotOf: string | null;
    parentSnapshot: string | null;
  }>;
  verdict: "REVIEW_BLOCKED";
  installEligible: false;
  findings: readonly InspectFinding[];
}>;

export type ArchiveEntrySummary = Readonly<{
  path: string;
  type: "file" | "directory";
  size: number;
  mode: number;
}>;

export type ArchiveInspectResult = Readonly<
  Omit<ChainMetadataInspectResult, "scope" | "findings"> & {
    scope: "ARCHIVE_PREFLIGHT";
    archive: Readonly<{
      format: "ustar+gzip";
      safety: "VERIFIED";
      expandedBytes: number;
      entries: number;
      files: number;
      directories: number;
      entrypointPresent: true;
      inventory: readonly ArchiveEntrySummary[];
    }>;
    findings: readonly InspectFinding[];
  }
>;

export type NativeAuditInspectResult = Readonly<
  Omit<ArchiveInspectResult, "scope" | "findings"> & {
    scope: "NATIVE_AUDIT";
    nativeAudit: Readonly<{
      tool: "zeroclaw skills audit";
      status: "PASSED";
      filesScanned: number;
    }>;
    findings: readonly InspectFinding[];
  }
>;

export type SemanticSignal = Readonly<{
  code: string;
  impact: "DENY" | "REVIEW_BLOCKED";
  path: string | null;
  line: number | null;
  message: string;
}>;

export type PolicyInspectResult = Readonly<
  Omit<NativeAuditInspectResult, "scope" | "status" | "verdict" | "findings"> & {
    status: "denied" | "review_blocked";
    scope: "SEMANTIC_POLICY";
    semanticScan: Readonly<{
      status: "PASSED" | "FINDINGS";
      filesScanned: number;
      textFiles: number;
      binaryFiles: number;
      signals: readonly SemanticSignal[];
    }>;
    verdict: "DENY" | "REVIEW_BLOCKED";
    findings: readonly InspectFinding[];
  }
>;

export type InspectResult = Readonly<
  Omit<
    PolicyInspectResult,
    "scope" | "status" | "inspectionId" | "installEligible" | "verdict" | "findings"
  > & {
    status: "denied" | "review_blocked" | "pass_requires_approval";
    scope: "PERSISTED_VERDICT";
    inspectionId: string;
    createdAt: string;
    expiresAt: string;
    trustPolicy: Readonly<{
      required: true;
      publisher: string;
      trusted: boolean;
      configuredAuthorities: number;
      source: "SKILLSEAL_TRUSTED_AUTHORITIES";
    }>;
    verdict: "DENY" | "REVIEW_BLOCKED" | "PASS_REQUIRES_APPROVAL";
    installEligible: boolean;
    findings: readonly InspectFinding[];
  }
>;

export type InspectFailure = Readonly<{
  service: "skillseal";
  version: string;
  status: "error";
  custody: "T0_READ";
  cluster: string;
  asset: string;
  code: string;
  message: string;
}>;

export type InspectionStatusResult = Readonly<{
  service: "skillseal";
  version: string;
  custody: "T0_READ";
  inspectionId: string;
  state: "BLOCKED" | "PENDING_APPROVAL" | "EXPIRED" | "CONSUMED";
  createdAt: string;
  expiresAt: string;
  expired: boolean;
  cluster: InspectCluster;
  asset: string;
  sha256: string;
  compressedBytes: number;
  frozen: boolean;
  publisher: string;
  verdict: "DENY" | "REVIEW_BLOCKED" | "PASS_REQUIRES_APPROVAL";
  installEligible: boolean;
  consumedAt: string | null;
  payloadStored: true;
}>;

export type InstallResult = Readonly<{
  service: "skillseal";
  version: string;
  status: "installed";
  custody: "T0_READ";
  localEffect: "HUMAN_APPROVED_SKILL_BUNDLE_WRITE";
  verdict: "INSTALLED_PINNED";
  inspectionId: string;
  receiptState: "CONSUMED";
  consumedAt: string;
  cluster: InspectCluster;
  asset: string;
  sha256: string;
  frozen: true;
  publisher: string;
  bundle: "skillseal_approved";
  directoryName: string;
  entrypoint: string;
  filesInstalled: number;
  payloadExecuted: false;
  requiresNewSession: true;
}>;

export type InstallFailure = Readonly<{
  service: "skillseal";
  version: string;
  status: "error";
  custody: "T0_READ";
  localEffect: "HUMAN_APPROVED_SKILL_BUNDLE_WRITE";
  inspectionId: string;
  code: string;
  message: string;
  receiptConsumed: boolean;
}>;
