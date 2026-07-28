import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const controlSkillUrl = new URL("../skills/skillseal/SKILL.md", import.meta.url);

test("public SkillSeal control skill documents concise recording commands", async () => {
  const skill = await readFile(controlSkillUrl, "utf8");

  assert.match(skill, /`\/inspect <cluster> <asset>`/);
  assert.match(skill, /`\/install`/);
  assert.match(skill, /most recent unambiguous, unexpired/);
});

test("public SkillSeal control skill requires concise English install output", async () => {
  const skill = await readFile(controlSkillUrl, "utf8");

  assert.match(skill, /use concise English/);
  assert.match(skill, /Inspection denied/);
  assert.match(skill, /Installation blocked/);
  assert.match(skill, /approvalPresented=false/);
  assert.match(skill, /Inspection passed/);
  assert.match(skill, /approvalRequired=true/);
  assert.match(skill, /Installation successful/);
  assert.match(skill, /verdict=INSTALLED_PINNED/);
  assert.match(skill, /payloadExecuted=false/);
  assert.match(skill, /requiresNewSession=true/);
  assert.doesNotMatch(skill, /newSessionRequired=true/);
  assert.doesNotMatch(skill, /restartRequired=true/);
});
