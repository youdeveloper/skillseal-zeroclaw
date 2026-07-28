import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import test from "node:test";

import {
  DevnetReleasePlanError,
  assertExecutionConfirmations,
  assertLivePreconditions,
  assertReleasedState,
  assertUpdatedRepo,
  buildOfflineReleasePlan,
  lineagePreservingManifest,
} from "../dist/release/devnet-plan.js";

const execFileAsync = promisify(execFile);
const REPO = "gMBKWhGPtf2JSJSvyybg7wYD5aZaGbXs7PK69hVe2RK";
const PUBLISHER = "DK5SkZ5Lui2WQkMZD3reHBPSTf166Xwmuqua5sfzStXS";
const PARENT = "DLvajTGajD2bHnvu12j44HQHXsLoYt2CSUpuBYubTeFc";
const OLD_SHA = "f51154e44a63cb7858805af37f1105e2ccda749c6d97f3cf974293b58320f457";
const NEW_SHA = "ac205b5411c74703f15d20be023b8adf18f44b6530560cb85bce787604311b6b";
const NEW_SNAPSHOT = "9sV7QDc3tBRgCs2p3fREu5fSWZmTqG1ppXCMpsLsSQqT";

const CONFIG = {
  cluster: "devnet",
  rpc: "https://api.devnet.solana.com",
  repoAsset: REPO,
  publisher: PUBLISHER,
  expectedCurrentName: "skillseal-guardian-demo",
  expectedCurrentVersion: "0.1.0",
  expectedCurrentLicense: "Apache-2.0",
  expectedCurrentEntrypoint: "SKILL.md",
  expectedCurrentSha256: OLD_SHA,
  expectedCurrentHead: PARENT,
  expectedParentSha256: OLD_SHA,
  candidateDirectory: "fixtures/competition-skill",
  candidateName: "skillseal-guardian-demo",
  candidateVersion: "0.2.0",
  candidateLicense: "Apache-2.0",
  candidateEntrypoint: "SKILL.md",
  candidateSha256: NEW_SHA,
};

const CANDIDATE = {
  name: "skillseal-guardian-demo",
  version: "0.2.0",
  license: "Apache-2.0",
  entrypoint: "SKILL.md",
  permissions: [],
  compressedBytes: 467,
  sha256: NEW_SHA,
};

function repo(overrides = {}) {
  return {
    cluster: "devnet",
    asset: REPO,
    owner: PUBLISHER,
    frozen: false,
    updateAuthority: PUBLISHER,
    standard: "onchain-skill/0.1",
    name: "skillseal-guardian-demo",
    version: "0.1.0",
    license: "Apache-2.0",
    entrypoint: "SKILL.md",
    permissions: "",
    sha256: OLD_SHA,
    head: PARENT,
    snapshotOf: null,
    parent: null,
    ...overrides,
  };
}

function parent(overrides = {}) {
  return {
    cluster: "devnet",
    asset: PARENT,
    owner: PUBLISHER,
    frozen: true,
    updateAuthority: null,
    standard: "onchain-skill/0.1",
    name: "skillseal-guardian-demo",
    version: "0.1.0",
    license: "Apache-2.0",
    entrypoint: "SKILL.md",
    permissions: "",
    sha256: OLD_SHA,
    head: null,
    snapshotOf: REPO,
    parent: null,
    ...overrides,
  };
}

test("offline plan is devnet-only, performs no I/O, and preserves the old head", () => {
  const plan = buildOfflineReleasePlan(CONFIG, CANDIDATE);
  assert.equal(plan.status, "DRY_RUN_READY");
  assert.equal(plan.networkAccessed, false);
  assert.equal(plan.keypairRead, false);
  assert.equal(plan.chainWrites, 0);
  assert.deepEqual(lineagePreservingManifest(CONFIG, CANDIDATE).extra, [
    { key: "head", value: PARENT },
  ]);
});

test("mainnet, candidate drift, and incomplete execution confirmations fail closed", () => {
  assert.throws(
    () => buildOfflineReleasePlan({ ...CONFIG, cluster: "mainnet-beta" }, CANDIDATE),
    (error) => error instanceof DevnetReleasePlanError && error.code === "CLUSTER_FORBIDDEN",
  );
  assert.throws(
    () => buildOfflineReleasePlan(CONFIG, { ...CANDIDATE, sha256: OLD_SHA }),
    (error) => error instanceof DevnetReleasePlanError && error.code === "CANDIDATE_MISMATCH",
  );
  assert.throws(
    () => assertExecutionConfirmations(CONFIG, CANDIDATE, { repo: REPO, parent: PARENT }),
    (error) =>
      error instanceof DevnetReleasePlanError && error.code === "EXECUTION_CONFIRMATION_MISMATCH",
  );
});

test("live preflight rejects an unexpected old head before signer loading", () => {
  assertLivePreconditions(CONFIG, repo(), parent());
  assert.throws(
    () => assertLivePreconditions(CONFIG, repo({ head: NEW_SNAPSHOT }), parent()),
    (error) => error instanceof DevnetReleasePlanError && error.code === "LIVE_REPO_MISMATCH",
  );
});

test("post-update and post-release verification bind the exact child lineage", () => {
  const updated = repo({ version: "0.2.0", sha256: NEW_SHA });
  assertUpdatedRepo(CONFIG, CANDIDATE, updated);
  const snapshot = parent({
    asset: NEW_SNAPSHOT,
    version: "0.2.0",
    sha256: NEW_SHA,
    parent: PARENT,
  });
  const finalRepo = updated;
  assertReleasedState(CONFIG, CANDIDATE, snapshot, { ...finalRepo, head: NEW_SNAPSHOT });
  assert.throws(
    () => assertReleasedState(CONFIG, CANDIDATE, { ...snapshot, parent: null }, { ...finalRepo, head: NEW_SNAPSHOT }),
    (error) => error instanceof DevnetReleasePlanError && error.code === "RELEASED_SNAPSHOT_MISMATCH",
  );
});

test("CLI defaults to an offline dry-run and does not read a configured keypair path", async () => {
  const { stdout, stderr } = await execFileAsync(process.execPath, ["scripts/devnet-release.mjs"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      SKILLSEAL_DEVNET_KEYPAIR: "/definitely/not/a/real/keypair.json",
    },
    timeout: 10_000,
    maxBuffer: 64 * 1024,
  });
  assert.equal(stderr, "");
  const result = JSON.parse(stdout);
  assert.equal(result.status, "DRY_RUN_READY");
  assert.equal(result.networkAccessed, false);
  assert.equal(result.keypairRead, false);
  assert.equal(result.chainWrites, 0);
});

test("CLI rejects conflicting live and execute modes before creating an RPC client", async () => {
  await assert.rejects(
    execFileAsync(
      process.execPath,
      ["scripts/devnet-release.mjs", "--live-preflight", "--execute"],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          SKILLSEAL_DEVNET_KEYPAIR: "/definitely/not/a/real/keypair.json",
        },
        timeout: 10_000,
        maxBuffer: 64 * 1024,
      },
    ),
    (error) => {
      const result = JSON.parse(error.stdout || error.stderr);
      return result.chainWriteStarted === false && result.manualVerificationRequired === false;
    },
  );
});
