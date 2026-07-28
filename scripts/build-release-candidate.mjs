import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { deterministicTarGz } from "../.tools/gitlana/src/dettar.mjs";
import { scanTarGzip } from "../dist/archive/scan.js";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const sourceDirectory = join(projectRoot, "fixtures", "competition-skill");
const outputDirectory = join(projectRoot, ".skillseal-data", "release-candidates");
const manifest = JSON.parse(await readFile(join(sourceDirectory, "gitlana.json"), "utf8"));
const archive = deterministicTarGz(sourceDirectory);
const sha256 = createHash("sha256").update(archive).digest("hex");
const scan = scanTarGzip(archive, manifest.entrypoint);
const baseName = `${manifest.name}-${manifest.version}`;
const archivePath = join(outputDirectory, `${baseName}.tar.gz`);
const receiptPath = join(outputDirectory, `${baseName}.json`);
const receipt = {
  source: "fixtures/competition-skill",
  standard: "onchain-skill/0.1",
  encoding: "tar+gzip",
  name: manifest.name,
  version: manifest.version,
  license: manifest.license,
  entrypoint: manifest.entrypoint,
  permissions: manifest.permissions,
  compressedBytes: archive.byteLength,
  expandedBytes: scan.summary.expandedBytes,
  sha256,
  archiveSafety: scan.summary.safety,
  inventory: scan.summary.inventory,
  networkAccessed: false,
  published: false,
};

await mkdir(outputDirectory, { recursive: true, mode: 0o700 });
await writeFile(archivePath, archive, { mode: 0o600 });
await chmod(archivePath, 0o600);
await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, {
  encoding: "utf8",
  mode: 0o600,
});
await chmod(receiptPath, 0o600);

console.log(JSON.stringify({ ...receipt, archivePath, receiptPath }, null, 2));
