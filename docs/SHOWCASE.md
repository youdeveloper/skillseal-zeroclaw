# SkillSeal showcase

## What I built

SkillSeal is a human-approved installation firewall for Gitlana skills hosted on Solana and consumed by ZeroClaw.

An operator sends a Solana Asset address to a real ZeroClaw agent through Telegram. SkillSeal verifies finalized chain metadata and the exact payload hash, scans the archive in quarantine, runs ZeroClaw's native skill audit, applies deterministic semantic and publisher-trust policy, and returns one of three clear decisions: `DENY`, `REVIEW_BLOCKED`, or `PASS_REQUIRES_APPROVAL`.

Even a passing result is not installed automatically. SkillSeal creates a short-lived, one-time receipt, while ZeroClaw keeps the installation tool in `always_ask`. The model cannot approve itself. After a human click, the installer revalidates the exact persisted bytes, consumes the receipt, and atomically writes a hash-pinned directory to a dedicated Skill Bundle without executing the payload. A new session is required before the Skill can load.

## Who it is for

SkillSeal is for ZeroClaw operators, teams, and marketplaces that want to distribute on-chain Skills without treating immutability as proof of safety. It is especially useful when an agent discovers a Skill by address but the human operator still owns the trust and installation decision.

## Why Solana matters

The demo uses a real Gitlana Repo and two immutable Devnet snapshots. Solana provides the public version lineage, owner, frozen state, payload bytes, and content hash. SkillSeal converts those chain facts into a local, reviewable, replay-resistant installation decision.

Public demo lineage:

- Repo: `gMBKWhGPtf2JSJSvyybg7wYD5aZaGbXs7PK69hVe2RK`
- v0.1 snapshot: `DLvajTGajD2bHnvu12j44HQHXsLoYt2CSUpuBYubTeFc`
- v0.2 child snapshot: `7XfnNChJq8qGK8CYeEcs7HxLD5MyeR1A8FgfPLbkTYgU`
- v0.2 SHA-256: `ac205b5411c74703f15d20be023b8adf18f44b6530560cb85bce787604311b6b`

## ZeroClaw features used

- Telegram channel and a real model-backed agent.
- ZeroClaw Skills for non-negotiable operating rules.
- A local stdio MCP Bundle for inspection, receipt status, and installation.
- A supervised risk profile with installation in `always_ask`.
- ZeroClaw native Skill audit over the exact quarantined payload.
- A dedicated approved Skill Bundle and fresh-session loading.

## Custody tier and threat model

Runtime Solana custody is T0 Read: public finalized RPC reads only, no wallet, no private key, no signing, no token movement, and no chain write. The only mutating runtime capability is a disclosed local filesystem installation outside the Solana custody ladder, held behind ZeroClaw's human approval UI.

The design defends against mutable-head swaps, untrusted publishers, prompt injection, secret requests, forbidden scripts and binaries, path traversal, links, archive bombs, persisted-payload tampering, expired receipts, concurrent replay, caller-selected destinations, fake chat approval, and activation inside the approving session.

`PASS_REQUIRES_APPROVAL` means all implemented checks passed; it does not claim that a Skill is harmless.

## What is custom

- Strict Gitlana/Metaplex account and manifest validation.
- Bounded in-memory gzip/ustar parser.
- Exact-byte quarantine integration with ZeroClaw native audit.
- Deterministic semantic and trust policy.
- SQLite evidence store and short-lived one-time receipts.
- Receipt-bound, tamper-detecting atomic installer.
- Devnet-only, lineage-safe authoring tool with offline-by-default interlocks.
- 35 passing security and integration tests covering both hostile and approved paths.

## Live result

The full Telegram path produced a real approval card, a pinned v0.2 installation with a consumed receipt, and the following exact fresh-session response:

```text
SKILLSEAL_GUARDIAN_DEMO_ACTIVE
approval=HUMAN
payload=PINNED
execution=READ_ONLY
```

No chain, wallet, MCP, or other network call occurred while the installed demo Skill produced that response.

## Links

- Source and setup: repository README
- Architecture: [`ARCHITECTURE.md`](ARCHITECTURE.md)
- Threat model: [`THREAT-MODEL.md`](THREAT-MODEL.md)
- Reproduction: [`REPRODUCE.md`](REPRODUCE.md)
- Final verification evidence: [`VERIFICATION.md`](VERIFICATION.md)
