# SkillSeal threat model

## Protected assets

- The integrity of the operator's local ZeroClaw Skill Bundles.
- The operator's secrets, wallet material, filesystem, and network authority.
- The binding between an inspected Solana Asset and installed local bytes.
- The human's exclusive authority to approve a local installation.
- The audit evidence needed to explain why a decision was made.

## Trust boundaries

SkillSeal treats all of the following as untrusted until verified: Telegram message text, model output, Gitlana metadata, archive content, `SKILL.md` instructions, filenames, archive modes, declared permissions, mutable Repo heads, and publisher identities not present in the local allowlist.

The operator trusts the locally reviewed SkillSeal code and policy, the configured ZeroClaw binary, the local host and SQLite store, the chosen trusted-publisher allowlist, and ZeroClaw's out-of-band approval UI. Solana RPC is an external dependency whose response is checked against expected account structure, ownership, payload length, SHA-256, and finalized commitment.

## Threats and controls

| Threat | Example | Control | Residual risk |
| --- | --- | --- | --- |
| Integrity confused with trust | A malicious publisher freezes a harmful archive with a valid hash | Local publisher allowlist plus content policy | Trusted publisher key compromise |
| Mutable-head TOCTOU | Repo content changes after review | Only frozen snapshots are eligible; exact Asset and hash are receipt-bound | Incorrect chain/RPC data outside validation assumptions |
| Prompt injection | `SKILL.md` tells the agent to ignore policy or reveal secrets | Content is evidence, never followed during inspection; deterministic signals block review | Novel phrasing may evade semantic rules |
| Script or executable payload | Archive contains `.sh`, `.mjs`, or an executable | Default policy denies script-like files and binaries | A text-only Skill can still contain harmful instructions |
| Archive traversal | `../../config.toml`, absolute paths, symlinks or hardlinks | Bounded ustar parser rejects unsafe paths and entry types; install revalidates | Parser implementation defect |
| Archive bomb | Tiny gzip expands to excessive bytes or files | Compressed, expanded, file-count, and path-length limits | Resource exhaustion below configured limits |
| Manifest ambiguity | Duplicate metadata, missing entrypoint, malformed types | Strict structural validation and fail-closed errors | Unsupported future standard requires an explicit update |
| Payload swap after inspection | Persisted evidence file is modified before install | File-type check, length check, SHA-256 recomputation, archive revalidation | Compromised local host can subvert the process |
| Receipt replay | Same approval is used more than once | SQLite `IMMEDIATE` transaction and atomic `consumed_at` transition | A crash after claim causes safe false-negative reinspection |
| Receipt race | Two concurrent installs use one receipt | Atomic claim plus per-hash exclusive lock | None expected within one protected local store |
| Stale approval | Human approves an old decision | Ten-minute receipt TTL and exact receipt binding | Human can still approve without reading findings |
| Fake chat approval | Model says “the user approved” | `install` remains in ZeroClaw `always_ask`; no approval argument exists | Misconfigured risk profile outside this project |
| Destination escape | Model supplies an alternate installation path | Installer accepts no path; target must remain inside dedicated bundle | Compromised local config can point the whole bundle elsewhere |
| Automatic activation | Newly installed instructions affect the approving session | Installation never executes; a fresh ZeroClaw session is required | Operator may later run a harmful but policy-missed Skill |
| Secret leakage | Payload requests wallet, token, environment variables, or local files | Secret-request policy findings; runtime uses no wallet; secrets excluded from repository | LLM/provider and host operational security remain external |
| RPC outage or malformed response | Devnet endpoint fails or returns incomplete data | No fallback to a weaker verdict; inspection fails closed | Availability loss |
| Publisher tool leakage | Demo release key becomes exposed | Publisher key is Devnet-only, ignored, permission-restricted, and absent from runtime | Devnet identity can be impersonated if the local key is stolen |

## Custody declaration

### Runtime inspection: T0 Read

- Public finalized Solana reads only.
- No wallet, seed phrase, private key, token transfer, transaction signing, or chain write.
- The MCP input accepts only `cluster` and a base58 Asset address.

### Approved installation: local side effect outside the custody ladder

- Writes only into the configured approved Skill Bundle.
- Requires an unexpired `PASS_REQUIRES_APPROVAL` receipt and a ZeroClaw human click.
- Uses exact persisted bytes and private local file modes.
- Never executes payload code during installation.
- API responses keep official Solana custody at `T0_READ` and separately declare `localEffect=HUMAN_APPROVED_SKILL_BUNDLE_WRITE`; this is not the bounty's T1 Build tier.

### Demo publishing: outside runtime scope

The Devnet-only publisher was used to create the public test lineage. It is not required to run SkillSeal, is not passed to the MCP server, and is not included in the repository.

## Verdict meaning

- `DENY`: deterministic local policy violation. It cannot be overridden.
- `REVIEW_BLOCKED`: required evidence or trust is incomplete. It cannot be installed.
- `PASS_REQUIRES_APPROVAL`: all implemented checks passed, but this is not a safety guarantee. A human decision is still mandatory.
- `INSTALLED_PINNED`: the exact eligible bytes were materialized locally and the receipt was consumed. It does not mean the content has executed.

## Known limitations

SkillSeal does not provide formal verification, malware sandbox execution, publisher reputation, revocation feeds, multi-RPC consensus, or a guarantee that natural-language instructions are harmless. The current default policy intentionally rejects scripts and declared permissions, which reduces utility in exchange for a narrow, demonstrable safety boundary.
