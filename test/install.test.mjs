import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { InstallError, installInspection } from "../dist/install/install.js";
import {
  getInspectionStatus,
  newInspectionId,
  persistInspection,
} from "../dist/store/inspections.js";

const ASSET = "DLvajTGajD2bHnvu12j44HQHXsLoYt2CSUpuBYubTeFc";
const PUBLISHER = "DK5SkZ5Lui2WQkMZD3reHBPSTf166Xwmuqua5sfzStXS";
const SKILL = Buffer.from(
  "---\nname: skillseal-safe-fixture\ndescription: Safe install test.\n---\n\n# Safe fixture\n",
);

function octal(value, length) {
  return value.toString(8).padStart(length - 1, "0") + "\0";
}

function header({ path, type = "file", content = Buffer.alloc(0), mode }) {
  const block = Buffer.alloc(512);
  block.write(path, 0, 100, "utf8");
  block.write(octal(mode ?? (type === "directory" ? 0o755 : 0o644), 8), 100);
  block.write(octal(0, 8), 108);
  block.write(octal(0, 8), 116);
  block.write(octal(type === "directory" ? 0 : content.length, 12), 124);
  block.write(octal(0, 12), 136);
  block.write("        ", 148);
  block.write(type === "file" ? "0" : type === "directory" ? "5" : type, 156);
  block.write("ustar\0", 257);
  block.write("00", 263);
  let checksum = 0;
  for (const byte of block) checksum += byte;
  block.write(checksum.toString(8).padStart(6, "0") + "\0 ", 148);
  return block;
}

function archive(entries) {
  const blocks = [];
  for (const entry of entries) {
    const content = entry.content ?? Buffer.alloc(0);
    blocks.push(header({ ...entry, content }));
    if (entry.type !== "directory" && content.length > 0) {
      blocks.push(content);
      const padding = (512 - (content.length % 512)) % 512;
      if (padding > 0) blocks.push(Buffer.alloc(padding));
    }
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks), { level: 9 });
}

function safeArchive() {
  return archive([
    { path: "SKILL.md", content: SKILL },
    {
      path: "gitlana.json",
      content: Buffer.from(
        '{"name":"skillseal-guardian-demo","version":"0.1.0","entrypoint":"SKILL.md","permissions":[]}\n',
      ),
    },
  ]);
}

function evidence({
  inspectionId,
  payload,
  createdAt = "2026-07-27T09:00:00.000Z",
  expiresAt = "2026-07-27T09:10:00.000Z",
  verdict = "PASS_REQUIRES_APPROVAL",
  installEligible = true,
  frozen = true,
  trusted = true,
}) {
  const sha256 = createHash("sha256").update(payload).digest("hex");
  return {
    inspectionId,
    createdAt,
    expiresAt,
    cluster: "devnet",
    asset: ASSET,
    assetOwner: PUBLISHER,
    manifest: {
      name: "skillseal-guardian-demo",
      entrypoint: "SKILL.md",
      permissions: [],
    },
    payload: { sha256, compressedBytes: payload.length, integrity: "VERIFIED" },
    chainState: {
      frozen,
      updateAuthorityType: frozen ? "None" : "Address",
    },
    archive: { safety: "VERIFIED" },
    nativeAudit: { status: "PASSED" },
    semanticScan: { status: "PASSED", signals: [] },
    trustPolicy: { publisher: PUBLISHER, trusted },
    verdict,
    installEligible,
  };
}

async function persist(root, result, payload) {
  await persistInspection({ result, compressedPayload: payload, dataDirectory: root });
}

test("one approved receipt installs exact files atomically and cannot be replayed", async () => {
  const root = await mkdtemp(join(process.cwd(), ".skillseal-data", "install-success-"));
  const approved = join(root, "approved");
  const payload = safeArchive();
  const inspectionId = newInspectionId("2026-07-27T09:00:00.000Z");
  const result = evidence({ inspectionId, payload });
  const sha256 = result.payload.sha256;

  try {
    await persist(root, result, payload);
    const installed = await installInspection({
      inspectionId,
      dataDirectory: root,
      approvedDirectory: approved,
      now: new Date("2026-07-27T09:05:00.000Z"),
    });

    assert.equal(installed.verdict, "INSTALLED_PINNED");
    assert.equal(installed.custody, "T0_READ");
    assert.equal(installed.localEffect, "HUMAN_APPROVED_SKILL_BUNDLE_WRITE");
    assert.equal(installed.receiptState, "CONSUMED");
    assert.equal(installed.payloadExecuted, false);
    assert.equal(installed.requiresNewSession, true);
    assert.equal(installed.filesInstalled, 2);
    assert.equal(installed.directoryName, `skillseal-guardian-demo-${sha256.slice(0, 12)}`);
    assert.deepEqual(
      await readFile(join(approved, installed.directoryName, "SKILL.md")),
      SKILL,
    );
    assert.deepEqual(await readdir(approved), [installed.directoryName]);

    const status = getInspectionStatus(inspectionId, {
      dataDirectory: root,
      now: new Date("2026-07-27T09:05:01.000Z"),
    });
    assert.equal(status.state, "CONSUMED");
    assert.equal(status.installEligible, false);
    assert.notEqual(status.consumedAt, null);

    await assert.rejects(
      installInspection({
        inspectionId,
        dataDirectory: root,
        approvedDirectory: approved,
        now: new Date("2026-07-27T09:05:02.000Z"),
      }),
      (error) =>
        error instanceof InstallError &&
        error.code === "RECEIPT_CONSUMED" &&
        error.receiptConsumed === true,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("DENY, REVIEW_BLOCKED, and expired receipts are rejected without being consumed", async () => {
  const root = await mkdtemp(join(process.cwd(), ".skillseal-data", "install-ineligible-"));
  const payload = safeArchive();
  const deniedId = newInspectionId("2026-07-27T09:00:00.000Z");
  const blockedId = newInspectionId("2026-07-27T09:00:00.000Z");
  const expiredId = newInspectionId("2026-07-27T08:00:00.000Z");

  try {
    await persist(
      root,
      evidence({
        inspectionId: deniedId,
        payload,
        verdict: "DENY",
        installEligible: false,
        trusted: false,
      }),
      payload,
    );
    await persist(
      root,
      evidence({
        inspectionId: blockedId,
        payload,
        verdict: "REVIEW_BLOCKED",
        installEligible: false,
        frozen: false,
        trusted: false,
      }),
      payload,
    );
    await persist(
      root,
      evidence({
        inspectionId: expiredId,
        payload,
        createdAt: "2026-07-27T08:00:00.000Z",
        expiresAt: "2026-07-27T08:10:00.000Z",
      }),
      payload,
    );

    await assert.rejects(
      installInspection({
        inspectionId: deniedId,
        dataDirectory: root,
        approvedDirectory: join(root, "approved"),
        now: new Date("2026-07-27T09:05:00.000Z"),
      }),
      (error) => error instanceof InstallError && error.code === "RECEIPT_NOT_INSTALLABLE",
    );
    await assert.rejects(
      installInspection({
        inspectionId: blockedId,
        dataDirectory: root,
        approvedDirectory: join(root, "approved"),
        now: new Date("2026-07-27T09:05:00.000Z"),
      }),
      (error) => error instanceof InstallError && error.code === "RECEIPT_NOT_INSTALLABLE",
    );
    await assert.rejects(
      installInspection({
        inspectionId: expiredId,
        dataDirectory: root,
        approvedDirectory: join(root, "approved"),
        now: new Date("2026-07-27T09:05:00.000Z"),
      }),
      (error) => error instanceof InstallError && error.code === "RECEIPT_EXPIRED",
    );
    assert.equal(
      getInspectionStatus(deniedId, {
        dataDirectory: root,
        now: new Date("2026-07-27T09:05:00.000Z"),
      }).consumedAt,
      null,
    );
    assert.equal(
      getInspectionStatus(blockedId, {
        dataDirectory: root,
        now: new Date("2026-07-27T09:05:00.000Z"),
      }).consumedAt,
      null,
    );
    assert.equal(
      getInspectionStatus(expiredId, {
        dataDirectory: root,
        now: new Date("2026-07-27T09:05:00.000Z"),
      }).consumedAt,
      null,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("tampered persisted bytes fail closed after the one-time receipt is claimed", async () => {
  const root = await mkdtemp(join(process.cwd(), ".skillseal-data", "install-tamper-"));
  const payload = safeArchive();
  const inspectionId = newInspectionId("2026-07-27T09:00:00.000Z");
  const result = evidence({ inspectionId, payload });

  try {
    await persist(root, result, payload);
    await writeFile(join(root, "inspections", inspectionId, "payload.tar.gz"), "tampered");
    await assert.rejects(
      installInspection({
        inspectionId,
        dataDirectory: root,
        approvedDirectory: join(root, "approved"),
        now: new Date("2026-07-27T09:05:00.000Z"),
      }),
      (error) =>
        error instanceof InstallError &&
        error.code === "EVIDENCE_PAYLOAD_MISMATCH" &&
        error.receiptConsumed === true,
    );
    assert.equal(
      getInspectionStatus(inspectionId, {
        dataDirectory: root,
        now: new Date("2026-07-27T09:05:01.000Z"),
      }).state,
      "CONSUMED",
    );
    await assert.rejects(access(join(root, "approved")));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("path traversal is revalidated and cannot escape the approved bundle", async () => {
  const root = await mkdtemp(join(process.cwd(), ".skillseal-data", "install-traversal-"));
  const payload = archive([
    { path: "SKILL.md", content: SKILL },
    { path: "../escape", content: Buffer.from("hostile") },
  ]);
  const inspectionId = newInspectionId("2026-07-27T09:00:00.000Z");

  try {
    await persist(root, evidence({ inspectionId, payload }), payload);
    await assert.rejects(
      installInspection({
        inspectionId,
        dataDirectory: root,
        approvedDirectory: join(root, "approved"),
        now: new Date("2026-07-27T09:05:00.000Z"),
      }),
      (error) =>
        error instanceof InstallError &&
        error.code === "ARCHIVE_REVALIDATION_FAILED" &&
        error.receiptConsumed === true,
    );
    await assert.rejects(access(join(root, "escape")));
    await assert.rejects(access(join(root, "approved")));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("concurrent replay attempts allow exactly one atomic installation", async () => {
  const root = await mkdtemp(join(process.cwd(), ".skillseal-data", "install-race-"));
  const approved = join(root, "approved");
  const payload = safeArchive();
  const inspectionId = newInspectionId("2026-07-27T09:00:00.000Z");

  try {
    await persist(root, evidence({ inspectionId, payload }), payload);
    const attempts = await Promise.allSettled([
      installInspection({
        inspectionId,
        dataDirectory: root,
        approvedDirectory: approved,
        now: new Date("2026-07-27T09:05:00.000Z"),
      }),
      installInspection({
        inspectionId,
        dataDirectory: root,
        approvedDirectory: approved,
        now: new Date("2026-07-27T09:05:00.000Z"),
      }),
    ]);
    assert.equal(attempts.filter((attempt) => attempt.status === "fulfilled").length, 1);
    const rejected = attempts.find((attempt) => attempt.status === "rejected");
    assert.ok(rejected);
    assert.ok(rejected.reason instanceof InstallError);
    assert.equal(rejected.reason.code, "RECEIPT_CONSUMED");
    assert.equal((await readdir(approved)).length, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
