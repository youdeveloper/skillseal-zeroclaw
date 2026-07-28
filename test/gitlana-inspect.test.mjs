import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  assessDecodedGitlanaAsset,
  inspectGitlanaAsset,
  InspectError,
  MPL_CORE_PROGRAM_ID,
} from "../dist/gitlana/inspect.js";

const ASSET = "CzXQeCXtpKzpzxQrB26srEe534G64i7C27R4ED5syoib";
const OWNER = "2aJmyx8sFka5EpofWZzQM9MC2ybgBGKXWXs6WSF8AthM";

function decodedAsset({ frozen = true, duplicate = false, badHash = false } = {}) {
  const data = Buffer.from("deterministic-test-archive");
  const sha256 = createHash("sha256").update(data).digest("hex");
  const attributes = [
    { key: "standard", value: "onchain-skill/0.1" },
    { key: "name", value: "safe-fixture" },
    { key: "version", value: "0.1.0" },
    { key: "license", value: "Apache-2.0" },
    { key: "encoding", value: "tar+gzip" },
    { key: "entrypoint", value: "SKILL.md" },
    { key: "permissions", value: "" },
    { key: "content_sha256", value: badHash ? "0".repeat(64) : sha256 },
    { key: "content_length", value: String(data.length) },
    { key: "snapshot_of", value: "6ZjdCaiu8v1vCK79i4A2DVRuboTUYw3YnkkxJZbZD6Lj" },
  ];
  if (duplicate) attributes.push({ key: "name", value: "ambiguous" });

  return {
    publicKey: ASSET,
    header: {
      executable: false,
      owner: MPL_CORE_PROGRAM_ID,
      lamports: { basisPoints: 1n, identifier: "SOL", decimals: 9 },
    },
    attributes: {
      authority: { type: "UpdateAuthority" },
      attributeList: attributes,
    },
    appDatas: [{ dataAuthority: { type: "UpdateAuthority" }, data }],
    owner: OWNER,
    updateAuthority: frozen
      ? { type: "None" }
      : { type: "Address", address: OWNER },
  };
}

test("metadata inspection verifies bytes but remains fail-closed", () => {
  const result = assessDecodedGitlanaAsset({
    cluster: "mainnet-beta",
    assetAddress: ASSET,
    slot: 123,
    decoded: decodedAsset(),
  });

  assert.equal(result.payload.integrity, "VERIFIED");
  assert.equal(result.chainState.frozen, true);
  assert.equal(result.verdict, "REVIEW_BLOCKED");
  assert.equal(result.installEligible, false);
  assert.equal(result.scope, "CHAIN_METADATA_ONLY");
  assert.ok(result.findings.some((finding) => finding.code === "ARCHIVE_SCAN_PENDING"));
});

test("mutable repo asset is explicitly surfaced as high risk", () => {
  const result = assessDecodedGitlanaAsset({
    cluster: "mainnet-beta",
    assetAddress: ASSET,
    slot: 124,
    decoded: decodedAsset({ frozen: false }),
  });

  assert.equal(result.chainState.frozen, false);
  assert.equal(result.chainState.updateAuthority, OWNER);
  assert.ok(
    result.findings.some(
      (finding) => finding.code === "MUTABLE_ASSET" && finding.severity === "HIGH",
    ),
  );
});

test("hash mismatch fails closed", () => {
  assert.throws(
    () =>
      assessDecodedGitlanaAsset({
        cluster: "mainnet-beta",
        assetAddress: ASSET,
        slot: 125,
        decoded: decodedAsset({ badHash: true }),
      }),
    (error) => error instanceof InspectError && error.code === "HASH_MISMATCH",
  );
});

test("duplicate manifest keys fail closed", () => {
  assert.throws(
    () =>
      assessDecodedGitlanaAsset({
        cluster: "mainnet-beta",
        assetAddress: ASSET,
        slot: 126,
        decoded: decodedAsset({ duplicate: true }),
      }),
    (error) => error instanceof InspectError && error.code === "AMBIGUOUS_ATTRIBUTES",
  );
});

test("invalid Solana address is rejected before any RPC request", async () => {
  let called = false;
  await assert.rejects(
    inspectGitlanaAsset({
      cluster: "mainnet-beta",
      asset: "not-an-address",
      fetchImpl: async () => {
        called = true;
        throw new Error("must not run");
      },
    }),
    (error) => error instanceof InspectError && error.code === "INVALID_PUBLIC_KEY",
  );
  assert.equal(called, false);
});
