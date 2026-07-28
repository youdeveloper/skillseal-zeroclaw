# Final verification evidence

This document contains the final evidence needed to evaluate the submitted use case.

## Deterministic local checks

The final public tree passes:

```text
npm run check: 35/35 tests passed
npm run release:candidate: passed
candidate networkAccessed: false
candidate published: false
```

The test suite covers malformed and ambiguous metadata, hash mismatch, unsafe archive paths and links, expansion limits, native-audit quarantine, prompt injection, secret requests, scripts, publisher trust, receipt expiry and replay, persisted-payload tampering, atomic installation, concurrent installation, and Devnet release interlocks.

The canonical v0.2 candidate is deterministic:

```text
name/version: skillseal-guardian-demo@0.2.0
compressed bytes: 467
expanded bytes: 3072
files: SKILL.md, gitlana.json
SHA-256: ac205b5411c74703f15d20be023b8adf18f44b6530560cb85bce787604311b6b
```

## Public Solana Devnet lineage

| Object | Address | Verified state |
| --- | --- | --- |
| Mutable Gitlana Repo | [`gMBKWhGPtf2JSJSvyybg7wYD5aZaGbXs7PK69hVe2RK`](https://explorer.solana.com/address/gMBKWhGPtf2JSJSvyybg7wYD5aZaGbXs7PK69hVe2RK?cluster=devnet) | Version `0.2.0`; head points to v0.2 |
| v0.1 snapshot | [`DLvajTGajD2bHnvu12j44HQHXsLoYt2CSUpuBYubTeFc`](https://explorer.solana.com/address/DLvajTGajD2bHnvu12j44HQHXsLoYt2CSUpuBYubTeFc?cluster=devnet) | Frozen genesis snapshot |
| v0.2 child snapshot | [`7XfnNChJq8qGK8CYeEcs7HxLD5MyeR1A8FgfPLbkTYgU`](https://explorer.solana.com/address/7XfnNChJq8qGK8CYeEcs7HxLD5MyeR1A8FgfPLbkTYgU?cluster=devnet) | Frozen; no update authority; parent is v0.1 |

The v0.2 Repo update, child-snapshot creation, payload write, freeze, and head switch produced six finalized Devnet transactions with `err=null`. Total cost was `0.00993572` Devnet SOL, which has no real-money value. The Devnet authoring key is not part of the submitted runtime and is not present in this repository.

## Real negative inspection

A third-party frozen Mainnet Gitlana snapshot was inspected through the real Telegram → ZeroClaw → SkillSeal path. Its chain metadata and payload SHA-256 were valid, its archive passed bounded preflight, and its exact bytes passed ZeroClaw native audit. SkillSeal still returned:

```text
verdict: DENY
installEligible: false
finding: SCRIPT_FILE_FORBIDDEN
```

This proves that frozen state and a correct on-chain hash are not treated as evidence of publisher trust or content safety.

## Real positive inspection and approval

The public v0.2 Devnet snapshot was inspected through the same Telegram agent path at a finalized slot. The final result verified:

```text
frozen: true
update authority: none
payload integrity: VERIFIED
archive safety: VERIFIED
ZeroClaw native audit: PASSED
semantic policy: PASSED
trusted publisher: true
verdict: PASS_REQUIRES_APPROVAL
installEligible: true
```

The installation request contained only the exact fresh `inspection_id`. ZeroClaw displayed its native approval control. Separate live attempts proved:

- **Deny** produced no installed files and left the receipt unconsumed;
- an expired receipt returned `RECEIPT_EXPIRED` before any local write;
- one-time **Approve** returned `INSTALLED_PINNED`;
- the approved receipt became `CONSUMED` and could not be replayed;
- installed files were byte-identical to the inspected v0.2 payload;
- installation returned `payloadExecuted=false` and `requiresNewSession=true`.

Official Solana custody remains `T0_READ`: the runtime holds no wallet or private key, signs no transaction, moves no token, and performs no chain write. The approved installation is separately disclosed as `localEffect=HUMAN_APPROVED_SKILL_BUNDLE_WRITE`, outside the bounty's Solana custody ladder.

## Fresh-session invocation

After a clean ZeroClaw restart, a new Telegram agent session loaded the pinned v0.2 Skill and returned its exact documented result:

```text
SKILLSEAL_GUARDIAN_DEMO_ACTIVE
approval=HUMAN
payload=PINNED
execution=READ_ONLY
```

Post-invocation checks found no new inspection receipt, no SkillSeal MCP call, no chain call, and no wallet access. The inspection store remained unchanged after the earlier receipt-consumption timestamp.

## Public-boundary checks

Before publication:

- tracked files were scanned for credential formats, private keys, personal absolute paths, and the private Bot handle;
- the public tree contained no Chinese-only operator notes;
- ignored runtime, recording, installed-skill, dependency, and secret directories were absent;
- the public README was read back from GitHub and matched the local SHA-256.
