import assert from "node:assert/strict";
import test from "node:test";

import {
  GITLANA_COMMIT,
  ZEROCLAW_VERSION,
  resolveZeroClawTarget,
} from "../scripts/bootstrap-tools.mjs";

test("tool bootstrap pins the verified ZeroClaw release and Gitlana commit", () => {
  assert.equal(ZEROCLAW_VERSION, "0.8.3");
  assert.equal(GITLANA_COMMIT, "8cf9ad23502fdb46e3d1a5f33187f4919a702d30");
  assert.deepEqual(resolveZeroClawTarget("darwin", "arm64"), {
    archive: "zeroclaw-aarch64-apple-darwin.tar.gz",
    sha256: "13b4292d30d2e2eb5200d62ea12879fcbc691fff4102b36439a82d2a0093124a",
    platform: "darwin",
    architecture: "arm64",
  });
  assert.equal(
    resolveZeroClawTarget("linux", "x64").sha256,
    "662abfa20afc5790538e69aebc1be60e188d34ba64f96fd81505bbcdd8edce44",
  );
});

test("tool bootstrap rejects unsupported platforms instead of guessing an artifact", () => {
  assert.throws(
    () => resolveZeroClawTarget("win32", "x64"),
    /unsupported ZeroClaw bootstrap target/,
  );
});
