import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod/v4";

import type { InspectFailure, InstallFailure, ProbeResult } from "./domain/verdict.js";
import { inspectGitlanaAsset, InspectError } from "./gitlana/inspect.js";
import { installInspection, InstallError } from "./install/install.js";
import { getInspectionStatus, InspectionStoreError } from "./store/inspections.js";

const server = new McpServer({
  name: "skillseal",
  version: "0.1.0",
});

server.registerTool(
  "probe",
  {
    title: "SkillSeal integration probe",
    description:
      "Read-only deterministic probe used to verify that ZeroClaw can call the local SkillSeal MCP server.",
    inputSchema: z.object({
      nonce: z
        .string()
        .regex(/^[A-Za-z0-9_-]{1,64}$/)
        .describe("A non-secret correlation value with at most 64 safe characters."),
    }),
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  async ({ nonce }) => {
    const result: ProbeResult = {
      service: "skillseal",
      version: "0.1.0",
      status: "ok",
      custody: "T0_READ",
      installMode: "HUMAN_APPROVAL_REQUIRED",
      nonce,
    };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result),
        },
      ],
      structuredContent: result,
    };
  },
);

server.registerTool(
  "inspect",
  {
    title: "Inspect a Gitlana on-chain skill",
    description:
      "Read and verify a Gitlana skill at a finalized Solana slot, safely preflight its archive, run ZeroClaw native audit in a quarantine directory, and apply deterministic SkillSeal semantic policy. This tool never executes or installs the payload.",
    inputSchema: z.object({
      cluster: z.enum(["devnet", "mainnet-beta"]),
      asset: z
        .string()
        .regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/)
        .describe("A base58 Solana address; never a private key."),
    }),
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  async ({ cluster, asset }) => {
    try {
      const result = await inspectGitlanaAsset({ cluster, asset });
      return {
        content: [{ type: "text", text: JSON.stringify(result) }],
        structuredContent: result,
      };
    } catch (error: unknown) {
      const failure: InspectFailure = {
        service: "skillseal",
        version: "0.1.0",
        status: "error",
        custody: "T0_READ",
        cluster,
        asset,
        code: error instanceof InspectError ? error.code : "INTERNAL_ERROR",
        message:
          error instanceof InspectError
            ? error.message
            : "Inspection failed closed because an internal error occurred.",
      };
      return {
        isError: true,
        content: [{ type: "text", text: JSON.stringify(failure) }],
        structuredContent: failure,
      };
    }
  },
);

server.registerTool(
  "status",
  {
    title: "Read a persisted SkillSeal inspection receipt",
    description:
      "Read the bounded status of a persisted inspection without returning its local evidence path or payload bytes.",
    inputSchema: z.object({
      inspection_id: z
        .string()
        .regex(/^ins_[0-9]{14}_[0-9a-f]{12}$/)
        .describe("The opaque inspection id returned by skillseal__inspect."),
    }),
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  async ({ inspection_id }) => {
    try {
      const result = getInspectionStatus(inspection_id);
      return {
        content: [{ type: "text", text: JSON.stringify(result) }],
        structuredContent: result,
      };
    } catch (error: unknown) {
      const failure = {
        service: "skillseal",
        version: "0.1.0",
        status: "error",
        custody: "T0_READ",
        inspectionId: inspection_id,
        code: error instanceof InspectionStoreError ? error.code : "INTERNAL_ERROR",
        message:
          error instanceof InspectionStoreError
            ? error.message
            : "Status lookup failed closed because an internal error occurred.",
      } as const;
      return {
        isError: true,
        content: [{ type: "text", text: JSON.stringify(failure) }],
        structuredContent: failure,
      };
    }
  },
);

server.registerTool(
  "install",
  {
    title: "Install one exact approved SkillSeal receipt",
    description:
      "Consume one unexpired PASS_REQUIRES_APPROVAL receipt and atomically materialize only its exact persisted, hash-matched, frozen payload into the dedicated skillseal_approved bundle. This local write must remain in ZeroClaw always_ask and never executes the payload.",
    inputSchema: z.object({
      inspection_id: z
        .string()
        .regex(/^ins_[0-9]{14}_[0-9a-f]{12}$/)
        .describe("The one-time inspection id returned by skillseal__inspect; no path or Asset override is accepted."),
    }),
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  async ({ inspection_id }) => {
    try {
      const result = await installInspection({ inspectionId: inspection_id });
      return {
        content: [{ type: "text", text: JSON.stringify(result) }],
        structuredContent: result,
      };
    } catch (error: unknown) {
      const failure: InstallFailure = {
        service: "skillseal",
        version: "0.1.0",
        status: "error",
        custody: "T0_READ",
        localEffect: "HUMAN_APPROVED_SKILL_BUNDLE_WRITE",
        inspectionId: inspection_id,
        code: error instanceof InstallError ? error.code : "INTERNAL_ERROR",
        message:
          error instanceof InstallError
            ? error.message
            : "Installation failed closed because an internal error occurred.",
        receiptConsumed: error instanceof InstallError ? error.receiptConsumed : false,
      };
      return {
        isError: true,
        content: [{ type: "text", text: JSON.stringify(failure) }],
        structuredContent: failure,
      };
    }
  },
);

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write("SkillSeal MCP server connected over stdio.\n");
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`SkillSeal MCP fatal error: ${message}\n`);
  process.exitCode = 1;
});
