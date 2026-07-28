import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

test("stdio MCP exposes a deterministic read-only probe", async () => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve("dist/index.js")],
  });
  const client = new Client({ name: "skillseal-smoke", version: "0.1.0" });

  try {
    await client.connect(transport);
    const listed = await client.listTools();
    assert.ok(listed.tools.some((tool) => tool.name === "probe"));
    assert.ok(listed.tools.some((tool) => tool.name === "inspect"));
    assert.ok(listed.tools.some((tool) => tool.name === "status"));
    const install = listed.tools.find((tool) => tool.name === "install");
    assert.ok(install);
    assert.equal(install.annotations?.readOnlyHint, false);
    assert.equal(install.annotations?.idempotentHint, false);

    const result = await client.callTool({
      name: "probe",
      arguments: { nonce: "day1-spike" },
    });

    assert.equal(result.isError, undefined);
    assert.deepEqual(result.structuredContent, {
      service: "skillseal",
      version: "0.1.0",
      status: "ok",
      custody: "T0_READ",
      installMode: "HUMAN_APPROVAL_REQUIRED",
      nonce: "day1-spike",
    });
  } finally {
    await client.close();
  }
});
