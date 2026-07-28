import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import Database from "better-sqlite3";

import {
  getInspectionStatus,
  newInspectionId,
  persistInspection,
} from "../dist/store/inspections.js";

test("inspection receipt atomically binds verdict metadata to exact payload bytes", async () => {
  const root = await mkdtemp(join(process.cwd(), ".skillseal-data", "store-test-"));
  const payload = Buffer.from("exact-reviewed-payload");
  const sha256 = createHash("sha256").update(payload).digest("hex");
  const createdAt = "2026-07-27T09:00:00.000Z";
  const inspectionId = newInspectionId(createdAt);
  const result = {
    inspectionId,
    createdAt,
    expiresAt: "2026-07-27T09:10:00.000Z",
    cluster: "devnet",
    asset: "CzXQeCXtpKzpzxQrB26srEe534G64i7C27R4ED5syoib",
    assetOwner: "2aJmyx8sFka5EpofWZzQM9MC2ybgBGKXWXs6WSF8AthM",
    payload: { sha256, compressedBytes: payload.length },
    chainState: { frozen: true },
    trustPolicy: {
      publisher: "2aJmyx8sFka5EpofWZzQM9MC2ybgBGKXWXs6WSF8AthM",
    },
    verdict: "PASS_REQUIRES_APPROVAL",
    installEligible: true,
  };

  try {
    await persistInspection({ result, compressedPayload: payload, dataDirectory: root });
    const storedPayload = await readFile(join(root, "inspections", inspectionId, "payload.tar.gz"));
    assert.deepEqual(storedPayload, payload);
    await access(join(root, "inspections", inspectionId, "evidence.json"));

    const database = new Database(join(root, "skillseal.sqlite3"), { readonly: true });
    try {
      const row = database.prepare("SELECT * FROM inspections WHERE id = ?").get(inspectionId);
      assert.equal(row.sha256, sha256);
      assert.equal(row.verdict, "PASS_REQUIRES_APPROVAL");
      assert.equal(row.install_eligible, 1);
    } finally {
      database.close();
    }

    const status = getInspectionStatus(inspectionId, {
      dataDirectory: root,
      now: new Date("2026-07-27T09:05:00.000Z"),
    });
    assert.equal(status.state, "PENDING_APPROVAL");
    assert.equal(status.installEligible, true);

    const expired = getInspectionStatus(inspectionId, {
      dataDirectory: root,
      now: new Date("2026-07-27T09:10:00.000Z"),
    });
    assert.equal(expired.state, "EXPIRED");
    assert.equal(expired.installEligible, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
