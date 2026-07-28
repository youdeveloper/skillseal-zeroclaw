import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const configUrl = new URL("../config/zeroclaw.example.toml", import.meta.url);
const policyUrl = new URL("../policies/default.toml", import.meta.url);

test("public ZeroClaw example exposes only implemented SkillSeal tools", async () => {
  const config = await readFile(configUrl, "utf8");
  assert.match(config, /auto_approve\s*=\s*\[[\s\S]*"skillseal__inspect"[\s\S]*\]/);
  assert.match(config, /always_ask\s*=\s*\["skillseal__install"\]/);
  assert.doesNotMatch(config, /skillseal__watch/);

  const autoApprove = config.match(/auto_approve\s*=\s*\[([\s\S]*?)\]/)?.[1] ?? "";
  assert.doesNotMatch(autoApprove, /skillseal__install/);
});

test("public policy mirror names the real approved bundle and remains fail closed", async () => {
  const policy = await readFile(policyUrl, "utf8");
  assert.match(policy, /allow_scripts\s*=\s*false/);
  assert.match(policy, /require_frozen_snapshot\s*=\s*true/);
  assert.match(policy, /require_trusted_authority\s*=\s*true/);
  assert.match(policy, /install_bundle\s*=\s*"skillseal_approved"/);
  assert.match(policy, /trusted_authorities\s*=\s*\[\]/);
});
