import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { deterministicTarGz } from "../.tools/gitlana/src/dettar.mjs";
import {
  OFFICIAL_DEVNET_RPC,
  assertExecutionConfirmations,
  assertLivePreconditions,
  assertReleasedState,
  assertUpdatedRepo,
  buildOfflineReleasePlan,
  lineagePreservingManifest,
} from "../dist/release/devnet-plan.js";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const configPath = join(projectRoot, "config", "devnet-release-plan.json");
let chainWriteStarted = false;

function parseArgs(argv) {
  const parsed = { execute: false, livePreflight: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--execute") {
      parsed.execute = true;
      continue;
    }
    if (argument === "--live-preflight") {
      parsed.livePreflight = true;
      continue;
    }
    if (["--confirm-repo", "--confirm-parent", "--confirm-sha"].includes(argument)) {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`${argument} requires an exact value.`);
      const key = argument === "--confirm-repo" ? "repo" : argument === "--confirm-parent" ? "parent" : "sha256";
      parsed[key] = value;
      index += 1;
      continue;
    }
    throw new Error(`unsupported argument: ${argument}`);
  }
  if (parsed.execute && parsed.livePreflight) {
    throw new Error("--execute and --live-preflight are mutually exclusive.");
  }
  return parsed;
}

function candidateFrom(manifest, archive) {
  return {
    name: manifest.name,
    version: manifest.version,
    license: manifest.license ?? "",
    entrypoint: manifest.entrypoint ?? "SKILL.md",
    permissions: manifest.permissions ?? [],
    compressedBytes: archive.byteLength,
    sha256: createHash("sha256").update(archive).digest("hex"),
  };
}

function chainState(cluster, asset, skill) {
  return {
    cluster,
    asset,
    owner: String(skill.owner),
    frozen: skill.frozen,
    updateAuthority: skill.updateAuthority === null ? null : String(skill.updateAuthority),
    standard: skill.attrs.standard,
    name: skill.attrs.name,
    version: skill.attrs.version,
    license: skill.attrs.license ?? "",
    entrypoint: skill.attrs.entrypoint,
    permissions: skill.attrs.permissions ?? "",
    sha256: skill.attrs.content_sha256,
    head: skill.attrs.head || null,
    snapshotOf: skill.attrs.snapshot_of || null,
    parent: skill.attrs.parent || null,
  };
}

async function retryVerified(label, loader, verifier) {
  let lastError;
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    try {
      const value = await loader();
      verifier(value);
      return value;
    } catch (error) {
      lastError = error;
      if (attempt < 5) await new Promise((resolveDelay) => setTimeout(resolveDelay, attempt * 2_000));
    }
  }
  throw new Error(`${label} did not reach the required verified state: ${lastError?.message ?? "unknown error"}`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const config = JSON.parse(await readFile(configPath, "utf8"));
  const candidateDirectory = resolve(projectRoot, config.candidateDirectory);
  const manifest = JSON.parse(await readFile(join(candidateDirectory, "gitlana.json"), "utf8"));
  const archive = deterministicTarGz(candidateDirectory);
  const candidate = candidateFrom(manifest, archive);
  const dryRun = buildOfflineReleasePlan(config, candidate);

  if (!args.execute && !args.livePreflight) {
    console.log(JSON.stringify(dryRun, null, 2));
    return;
  }

  let keypairPath;
  if (args.execute) {
    assertExecutionConfirmations(config, candidate, args);
    keypairPath = process.env.SKILLSEAL_DEVNET_KEYPAIR;
    if (!keypairPath) throw new Error("SKILLSEAL_DEVNET_KEYPAIR is required only for --execute.");
  }

  const { fetchSkill, makeUmi, release, updateHead } = await import("../.tools/gitlana/src/chain.mjs");
  const readUmi = makeUmi({ rpc: OFFICIAL_DEVNET_RPC });
  const liveRepo = chainState("devnet", config.repoAsset, await fetchSkill(readUmi, config.repoAsset));
  const liveParent = chainState(
    "devnet",
    config.expectedCurrentHead,
    await fetchSkill(readUmi, config.expectedCurrentHead),
  );
  assertLivePreconditions(config, liveRepo, liveParent);

  if (args.livePreflight) {
    console.log(
      JSON.stringify(
        {
          service: "skillseal-devnet-release",
          version: "0.1.0",
          status: "LIVE_PREFLIGHT_VERIFIED",
          cluster: "devnet",
          repo: liveRepo,
          parent: liveParent,
          candidate,
          networkAccessed: true,
          keypairRead: false,
          chainWrites: 0,
        },
        null,
        2,
      ),
    );
    return;
  }

  let signingUmi;
  try {
    signingUmi = makeUmi({ rpc: OFFICIAL_DEVNET_RPC, keypairPath });
  } catch {
    throw new Error("devnet signer could not be loaded from the approved local keypair file.");
  }
  if (String(signingUmi.identity.publicKey) !== config.publisher) {
    throw new Error("devnet signer does not match the pinned publisher address.");
  }

  const updateManifest = lineagePreservingManifest(config, candidate);
  chainWriteStarted = true;
  await updateHead(signingUmi, {
    assetAddress: config.repoAsset,
    manifest: updateManifest,
    archive,
    log: (message) => process.stderr.write(`[devnet] ${message}\n`),
  });

  await retryVerified(
    "updated Repo",
    async () => chainState("devnet", config.repoAsset, await fetchSkill(readUmi, config.repoAsset)),
    (state) => assertUpdatedRepo(config, candidate, state),
  );

  const snapshotAddress = String(
    await release(signingUmi, {
      assetAddress: config.repoAsset,
      log: (message) => process.stderr.write(`[devnet] ${message}\n`),
    }),
  );

  const finalState = await retryVerified(
    "released snapshot",
    async () => {
      const [snapshot, repo] = await Promise.all([
        fetchSkill(readUmi, snapshotAddress),
        fetchSkill(readUmi, config.repoAsset),
      ]);
      return {
        snapshot: chainState("devnet", snapshotAddress, snapshot),
        repo: chainState("devnet", config.repoAsset, repo),
      };
    },
    ({ snapshot, repo }) => assertReleasedState(config, candidate, snapshot, repo),
  );

  const evidence = {
    service: "skillseal-devnet-release",
    version: "0.1.0",
    status: "RELEASED_AND_VERIFIED",
    cluster: "devnet",
    repoAsset: config.repoAsset,
    previousSnapshot: config.expectedCurrentHead,
    newSnapshot: snapshotAddress,
    candidate,
    snapshot: finalState.snapshot,
    repo: finalState.repo,
    privateKeyIncluded: false,
  };
  const evidenceDirectory = join(projectRoot, ".skillseal-data", "releases");
  const evidencePath = join(evidenceDirectory, `${candidate.name}-${candidate.version}.json`);
  await mkdir(evidenceDirectory, { recursive: true, mode: 0o700 });
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  await chmod(evidencePath, 0o600);
  console.log(JSON.stringify({ ...evidence, evidencePath }, null, 2));
}

main().catch((error) => {
  console.error(
    JSON.stringify({
      service: "skillseal-devnet-release",
      status: "ERROR",
      message: error instanceof Error ? error.message : "unknown error",
      chainWriteStarted,
      manualVerificationRequired: chainWriteStarted,
    }),
  );
  process.exitCode = 1;
});
