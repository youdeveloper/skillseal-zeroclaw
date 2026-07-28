import assert from "node:assert/strict";
import test from "node:test";

import { evaluateTrustPolicy, TrustPolicyError } from "../dist/policy/trust.js";

const PUBLISHER = "2aJmyx8sFka5EpofWZzQM9MC2ybgBGKXWXs6WSF8AthM";

test("trusted-authority policy is empty and fail-closed by default", () => {
  const previous = process.env.SKILLSEAL_TRUSTED_AUTHORITIES;
  delete process.env.SKILLSEAL_TRUSTED_AUTHORITIES;
  try {
    const result = evaluateTrustPolicy(PUBLISHER);
    assert.equal(result.trusted, false);
    assert.equal(result.configuredAuthorities, 0);
  } finally {
    if (previous === undefined) delete process.env.SKILLSEAL_TRUSTED_AUTHORITIES;
    else process.env.SKILLSEAL_TRUSTED_AUTHORITIES = previous;
  }
});

test("publisher must exactly match an explicitly configured authority", () => {
  const previous = process.env.SKILLSEAL_TRUSTED_AUTHORITIES;
  process.env.SKILLSEAL_TRUSTED_AUTHORITIES = PUBLISHER;
  try {
    assert.equal(evaluateTrustPolicy(PUBLISHER).trusted, true);
  } finally {
    if (previous === undefined) delete process.env.SKILLSEAL_TRUSTED_AUTHORITIES;
    else process.env.SKILLSEAL_TRUSTED_AUTHORITIES = previous;
  }
});

test("invalid trust configuration fails closed", () => {
  const previous = process.env.SKILLSEAL_TRUSTED_AUTHORITIES;
  process.env.SKILLSEAL_TRUSTED_AUTHORITIES = "not-an-address";
  try {
    assert.throws(
      () => evaluateTrustPolicy(PUBLISHER),
      (error) => error instanceof TrustPolicyError && error.code === "INVALID_TRUSTED_AUTHORITY",
    );
  } finally {
    if (previous === undefined) delete process.env.SKILLSEAL_TRUSTED_AUTHORITIES;
    else process.env.SKILLSEAL_TRUSTED_AUTHORITIES = previous;
  }
});
