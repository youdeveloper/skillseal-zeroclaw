import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { runZeroClawNativeAudit } from "../dist/audit/zeroclaw.js";

test("native audit materializes only preflight-approved bytes and parses its receipt", async () => {
  const skill = Buffer.from("---\nname: safe\n---\n");
  const scanned = {
    summary: {
      format: "ustar+gzip",
      safety: "VERIFIED",
      expandedBytes: 2048,
      entries: 2,
      files: 1,
      directories: 1,
      entrypointPresent: true,
      inventory: [
        { path: "nested", type: "directory", size: 0, mode: 0o755 },
        { path: "SKILL.md", type: "file", size: skill.length, mode: 0o644 },
      ],
    },
    files: new Map([["SKILL.md", skill]]),
  };

  const receipt = await runZeroClawNativeAudit(scanned, {
    dataDirectory: join(process.cwd(), ".skillseal-data", "test-audit"),
    runner: async (sourceDirectory) => {
      assert.deepEqual(await readFile(join(sourceDirectory, "SKILL.md")), skill);
      return {
        stdout: `  ✓ Skill audit passed for ${sourceDirectory} (1 files scanned).\n`,
        stderr: "",
      };
    },
  });

  assert.deepEqual(receipt, {
    tool: "zeroclaw skills audit",
    status: "PASSED",
    filesScanned: 1,
  });
});
