# Reproducing SkillSeal

This guide separates deterministic local verification from the optional real Telegram demonstration. Inspecting the public Devnet snapshot requires no wallet, private key, SOL, or chain write.

## 1. Verify the repository locally

Requirements: Node.js 20+, npm, Git, and `tar`.

```bash
npm ci
npm run bootstrap:tools
npm run check
npm run release:candidate
```

`bootstrap:tools` pins and verifies:

- ZeroClaw `v0.8.3`, including a platform-specific release SHA-256.
- Gitlana commit `8cf9ad23502fdb46e3d1a5f33187f4919a702d30`.

The test suite is deterministic and does not require Solana. `release:candidate` builds the exact local v0.2 fixture archive and verifies its expected hash.

## 2. Prepare an isolated runtime profile

Build first:

```bash
npm run build
mkdir -p .recording/data .recording/approved
chmod 700 .recording .recording/data .recording/approved
```

Before starting ZeroClaw, provide runtime paths and the public demo publisher address through the process environment. These values contain no private key:

```bash
export SKILLSEAL_DATA_DIR="$PWD/.recording/data"
export SKILLSEAL_APPROVED_DIR="$PWD/.recording/approved"
export SKILLSEAL_ZEROCLAW_BIN="$PWD/.tools/zeroclaw-v0.8.3/zeroclaw"
export SKILLSEAL_RPC_DEVNET="https://api.devnet.solana.com"
export SKILLSEAL_TRUSTED_AUTHORITIES="DK5SkZ5Lui2WQkMZD3reHBPSTf166Xwmuqua5sfzStXS"
```

Do not add a Bot Token, provider credential, private RPC key, or wallet keypair to `.env`, shell history, screenshots, or tracked files.

## 3. Configure ZeroClaw

Copy and adapt [`config/zeroclaw.example.toml`](../config/zeroclaw.example.toml) into an isolated ZeroClaw config directory. Replace all `/absolute/path` placeholders. The fragment must be merged with the operator's provider, agent, and channel settings.

Keep these ZeroClaw security properties unchanged:

```text
risk level: supervised
skillseal__install: always_ask
skillseal__install: absent from auto_approve
```

SkillSeal separately enforces `allow_scripts=false`, frozen snapshots, bounded archives, a ten-minute receipt TTL, and an empty-by-default trusted-publisher policy inside the MCP server. [`policies/default.toml`](../policies/default.toml) is an auditable mirror of that deliberately non-weakenable v0.1 policy.

Configure the model provider and Telegram Bot through ZeroClaw's own secret-aware configuration flow. A Telegram channel is optional for local tests but required to reproduce the real-channel showcase.

Start the isolated daemon with its config directory:

```bash
./.tools/zeroclaw-v0.8.3/zeroclaw --config-dir /absolute/path/to/isolated-config daemon
```

## 4. Inspect the public v0.2 snapshot

From the bound Telegram conversation, ask the agent to call `skillseal__inspect` with:

```text
cluster: devnet
asset: 7XfnNChJq8qGK8CYeEcs7HxLD5MyeR1A8FgfPLbkTYgU
```

Expected security-relevant fields:

```text
name/version: skillseal-guardian-demo@0.2.0
frozen: true
parentSnapshot: DLvajTGajD2bHnvu12j44HQHXsLoYt2CSUpuBYubTeFc
sha256: ac205b5411c74703f15d20be023b8adf18f44b6530560cb85bce787604311b6b
verdict: PASS_REQUIRES_APPROVAL
installEligible: true
semantic signals: []
```

The finalized slot and new `inspection_id` will differ. The receipt expires after ten minutes.

## 5. Exercise the approval boundary

Ask the agent to call `skillseal__install` with only the exact fresh `inspection_id`.

ZeroClaw must display its native approval control. First-time reviewers can click **Deny** to prove that chat text is not sufficient and that no files are written. Run a fresh inspection before an approved attempt.

For an approved attempt, click one-time **Approve**, not **Always**. Expected fields:

```text
status: installed
verdict: INSTALLED_PINNED
receiptState: CONSUMED
payloadExecuted: false
requiresNewSession: true
```

Do not approve if the Asset, hash, publisher, verdict, or tool argument differs from the inspection output.

## 6. Load in a fresh session

Restart the isolated ZeroClaw daemon with the same configuration. Ask the newly created session to run `skillseal-guardian-demo` and return only its specified result.

Expected output:

```text
SKILLSEAL_GUARDIAN_DEMO_ACTIVE
approval=HUMAN
payload=PINNED
execution=READ_ONLY
```

The demo Skill itself makes no MCP, Solana, wallet, or other network call.

## Optional release-plan audit

```bash
npm run release:devnet
```

Without explicit execution arguments and a separately configured Devnet keypair, this command performs an offline dry-run only. Mainnet is unsupported by design. A reviewer does not need to publish a new snapshot to reproduce the bounty use case.
