import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { access, chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));

export const ZEROCLAW_VERSION = "0.8.3";
export const GITLANA_COMMIT = "8cf9ad23502fdb46e3d1a5f33187f4919a702d30";
const ZEROCLAW_RELEASE_BASE =
  `https://github.com/zeroclaw-labs/zeroclaw/releases/download/v${ZEROCLAW_VERSION}`;
const GITLANA_REPOSITORY = "https://github.com/tonbistudio/gitlana.git";

const ZEROCLAW_TARGETS = Object.freeze({
  "darwin-arm64": {
    archive: "zeroclaw-aarch64-apple-darwin.tar.gz",
    sha256: "13b4292d30d2e2eb5200d62ea12879fcbc691fff4102b36439a82d2a0093124a",
  },
  "darwin-x64": {
    archive: "zeroclaw-x86_64-apple-darwin.tar.gz",
    sha256: "b85761b90429e101369b8f93b3558b8bc54b47c4fbb7052a4f1913dbebd1ab7d",
  },
  "linux-arm64": {
    archive: "zeroclaw-aarch64-unknown-linux-gnu.tar.gz",
    sha256: "d910d98821f13eaf7cd2037785fd95bb0a9e14700cb71cadea9c8d9328cf8e66",
  },
  "linux-x64": {
    archive: "zeroclaw-x86_64-unknown-linux-gnu.tar.gz",
    sha256: "662abfa20afc5790538e69aebc1be60e188d34ba64f96fd81505bbcdd8edce44",
  },
});

export function resolveZeroClawTarget(platform = process.platform, architecture = process.arch) {
  const key = `${platform}-${architecture}`;
  const target = ZEROCLAW_TARGETS[key];
  if (!target) {
    throw new Error(`unsupported ZeroClaw bootstrap target: ${key}`);
  }
  return { ...target, platform, architecture };
}

async function exists(path) {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function download(url) {
  const response = await fetch(url, { redirect: "follow" });
  if (!response.ok) throw new Error(`download failed with HTTP ${response.status}: ${url}`);
  return Buffer.from(await response.arrayBuffer());
}

async function installZeroClaw(toolsRoot) {
  const target = resolveZeroClawTarget();
  const destination = join(toolsRoot, `zeroclaw-v${ZEROCLAW_VERSION}`);
  const binary = join(destination, "zeroclaw");
  if (await exists(binary)) {
    const { stdout } = await execFileAsync(binary, ["--version"], { encoding: "utf8" });
    if (!stdout.includes(`zeroclaw ${ZEROCLAW_VERSION}`)) {
      throw new Error("existing ZeroClaw binary does not match the pinned version.");
    }
    return { status: "already-present", version: ZEROCLAW_VERSION, binary };
  }

  await mkdir(destination, { recursive: true, mode: 0o700 });
  const archiveBytes = await download(`${ZEROCLAW_RELEASE_BASE}/${target.archive}`);
  const actualSha256 = createHash("sha256").update(archiveBytes).digest("hex");
  if (actualSha256 !== target.sha256) {
    throw new Error("downloaded ZeroClaw archive failed the pinned SHA-256 check.");
  }
  const archivePath = join(destination, target.archive);
  await writeFile(archivePath, archiveBytes, { mode: 0o600 });
  await execFileAsync("tar", ["-xzf", archivePath, "-C", destination]);
  await chmod(binary, 0o700);
  return {
    status: "installed",
    version: ZEROCLAW_VERSION,
    binary,
    archive: target.archive,
    sha256: actualSha256,
  };
}

async function installGitlana(toolsRoot) {
  const destination = join(toolsRoot, "gitlana");
  const gitDirectory = join(destination, ".git");
  if (!(await exists(gitDirectory))) {
    await execFileAsync("git", [
      "clone",
      "--filter=blob:none",
      "--no-checkout",
      GITLANA_REPOSITORY,
      destination,
    ]);
    await execFileAsync("git", ["checkout", "--detach", GITLANA_COMMIT], { cwd: destination });
  }
  const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], {
    cwd: destination,
    encoding: "utf8",
  });
  if (stdout.trim() !== GITLANA_COMMIT) {
    throw new Error("existing Gitlana checkout does not match the pinned commit.");
  }
  await execFileAsync("npm", ["ci", "--omit=dev"], {
    cwd: destination,
    env: { ...process.env, npm_config_audit: "false", npm_config_fund: "false" },
  });
  return { status: "ready", commit: GITLANA_COMMIT, directory: destination };
}

export async function bootstrapTools(root = projectRoot) {
  const toolsRoot = join(root, ".tools");
  await mkdir(toolsRoot, { recursive: true, mode: 0o700 });
  const zeroClaw = await installZeroClaw(toolsRoot);
  const gitlana = await installGitlana(toolsRoot);
  return { zeroClaw, gitlana };
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  bootstrapTools()
    .then((result) => console.log(JSON.stringify(result, null, 2)))
    .catch((error) => {
      console.error(error instanceof Error ? error.message : "tool bootstrap failed");
      process.exitCode = 1;
    });
}
