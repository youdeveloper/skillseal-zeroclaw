import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { deterministicTarGz } from "../.tools/gitlana/src/dettar.mjs";
import { scanTarGzip } from "../dist/archive/scan.js";
import { runZeroClawNativeAudit } from "../dist/audit/zeroclaw.js";
import { scanSemanticPolicy } from "../dist/policy/semantic.js";

const FIXTURE = join(process.cwd(), "fixtures", "competition-skill");
const EXPECTED_RESPONSE = [
  "SKILLSEAL_GUARDIAN_DEMO_ACTIVE",
  "approval=HUMAN",
  "payload=PINNED",
  "execution=READ_ONLY",
].join("\n");

function frontmatter(text) {
  const match = /^---\n([\s\S]*?)\n---\n/.exec(text);
  assert.ok(match, "SKILL.md must contain YAML frontmatter");
  return Object.fromEntries(
    match[1]
      .split("\n")
      .map((line) => line.split(/:\s*/, 2))
      .filter((parts) => parts.length === 2),
  );
}

test("competition Skill metadata and documented response are internally consistent", async () => {
  const skill = await readFile(join(FIXTURE, "SKILL.md"), "utf8");
  const manifest = JSON.parse(await readFile(join(FIXTURE, "gitlana.json"), "utf8"));
  const metadata = frontmatter(skill);

  assert.equal(metadata.name, manifest.name);
  assert.equal(metadata.version, manifest.version);
  assert.equal(manifest.name, "skillseal-guardian-demo");
  assert.equal(manifest.version, "0.2.0");
  assert.equal(manifest.entrypoint, "SKILL.md");
  assert.deepEqual(manifest.permissions, []);
  assert.ok(skill.includes(EXPECTED_RESPONSE));
});

test("competition Skill builds deterministically and passes the complete local safety pipeline", async () => {
  const manifest = JSON.parse(await readFile(join(FIXTURE, "gitlana.json"), "utf8"));
  const first = deterministicTarGz(FIXTURE);
  const second = deterministicTarGz(FIXTURE);
  assert.deepEqual(first, second);

  const scanned = scanTarGzip(first, manifest.entrypoint);
  assert.equal(scanned.summary.safety, "VERIFIED");
  assert.equal(scanned.summary.entrypointPresent, true);
  assert.deepEqual(
    scanned.summary.inventory.map((entry) => entry.path),
    ["SKILL.md", "gitlana.json"],
  );

  const semantic = scanSemanticPolicy({
    files: scanned.files,
    declaredPermissions: manifest.permissions,
  });
  assert.equal(semantic.status, "PASSED");
  assert.equal(semantic.verdictImpact, "PASS");
  assert.deepEqual(semantic.signals, []);

  const nativeAudit = await runZeroClawNativeAudit(scanned, {
    dataDirectory: join(process.cwd(), ".skillseal-data", "release-candidate-test"),
  });
  assert.equal(nativeAudit.status, "PASSED");
  assert.ok(nativeAudit.filesScanned >= scanned.summary.files);
});
