# VaultForge Encrypted Vault — Design Report

Status: **M1 (crypto primitives + serialization), M2 (init + unlock), the safe
persistence foundation, and M3 entry CRUD are implemented and tested; later
milestones remain unimplemented.**
Companion document: `docs/VAULT_FORMAT.md` (frozen v1 byte-level format).

This report records the architecture, threat model, decisions, and acceptance
criteria for the local-first encrypted vault. Milestones M1–M3 and the safe
persistence foundation are built; backups and later milestones remain
unimplemented.

---

## 1. Repository baseline (verified this session)

- Git branch `master`, one commit `6feda20`; all current work is **untracked**.
- Python 3.11.2; project floor `requires-python = ">=3.10"`; CI matrix 3.10–3.13.
- Installed: typer 0.27.3, pytest 9.1.1, ruff 0.17.0, mypy 2.4.0, PyOTP 2.10.0,
  cryptography 46.0.7 (OpenSSL 3.5.6). Latest cryptography on PyPI is 50.0.2.
- Checks rerun at implementation time: **292 passed**, `ruff check` clean,
  `ruff format --check` clean, `mypy` clean (13 source files).
- `cryptography` is now a declared runtime dependency (`cryptography>=44`) in
  `pyproject.toml`.

## 2. Scope

In scope: a local, offline, single-user encrypted vault storing logins, TOTP
secrets, recovery codes, and notes; encrypted backups; integrity validation.

Out of scope (documented, not hidden): network sync, multi-user/server auth,
recovery of any kind, persistent session agent, virtual filesystem/mount,
sharing, browser integration, post-quantum algorithms.

## 3. Threat model

### 3.1 Assets
Master password (never stored); KEK and per-write DEK; plaintext vault contents;
vault and backup files; availability of the data.

### 3.2 Trust boundaries and assumptions
User → CLI → filesystem → OS → dependencies; no network. Assumed sound: the OS
CSPRNG, the Python runtime and stdlib, the `cryptography` library, a strong
user-chosen password, and the absence of an attacker on the machine while
unlocked.

### 3.3 Attacker capabilities
Holds the file; can modify/truncate/craft it; observes metadata (size, mtime,
permissions); guesses passwords offline; may attack the dependency supply chain;
may cause denial of service via crafted parameters or oversized files; may run
malware as the same user. Assumed unable to break Argon2id or ChaCha20-Poly1305.

### 3.4 Threats, mitigations, residual risk

| Threat | Mitigation | Residual |
|---|---|---|
| File stolen at rest | Argon2id + AEAD | Weak password falls to offline guessing |
| Offline guessing | Memory-hard KDF, strong params, per-vault salt | Proportional to password entropy |
| Tampering / downgrade of params | AAD covers version, vault_id, KDF params, salt, nonces; fixed v1 profile | Detected, not prevented |
| Rollback to an older valid file | Not addressed in v1 | Attacker may swap an old vault/backup |
| Malformed/malicious file | Fixed binary header, strict ordered validation, JSON only | Parser bugs |
| Corruption/truncation | Size gate + tags + distinct errors | Loss without a backup |
| Secret leakage in logs/errors | No secret logging; unified sanitized errors; stdout-only secrets | Shell history, scrollback, `ps` |
| Overly open permissions | `0600`/`0700`; warn on group/other access | User may relax permissions |
| Backup/sync copies | Encrypted backups, unique names, no overwrite | Cloud/sync tools keep old copies |
| Memory/swap/core dumps | Best-effort `bytearray` reuse | Python cannot reliably zeroize |
| Supply chain | Minimal deps; pinned; hashes in CI | Upstream compromise |
| KDF/DoS | Strict bounds checked before Argon2id/allocation | Attacker forces max allowed work |
| Compromised OS / malware as user | None effective | Out of scope |

### 3.5 Out of scope
Compromised OS/kernel/rootkit/keylogger/screen capture; physical coercion;
evil-maid firmware; side channels; post-unlock exfiltration; deniability;
remote sync; multi-user auth; quantum attacks (note comfortable AES/ChaCha
margins under Grover).

### 3.6 Encryption's limits
Encryption protects confidentiality and integrity **at rest** and raises the
cost of **offline** guessing. It does **not** protect a weak password, a
compromised endpoint, data **while unlocked**, file existence/size, or old
copies retained by backups and sync tools.

## 4. Cryptographic decisions

- **Dependency: `cryptography`** (Apache-2.0 OR BSD-3-Clause; actively
  maintained; Rust-backed; already exposes the required APIs). `argon2-cffi` is
  a credible alternative but would add a second crypto dependency; not chosen.
- **KDF: Argon2id** (RFC 9106), fixed v1 profile `m=65536 KiB, t=3, p=1`,
  32-byte output. Measured on this machine: ~64 ms (19 MiB/t=2), ~347 ms
  (64 MiB/t=3), ~1960 ms (256 MiB/t=4). 64 MiB/t=3 is a deliberate balance.
- **AEAD: ChaCha20-Poly1305** (RFC 8439) for both the DEK wrap and the body.
  Chosen over AES-256-GCM for constant-time behavior in software, portability,
  and a simple 12-byte-nonce requirement. **No algorithm agility in v1.**
- **Envelope encryption:** Argon2id yields the KEK; a random 32-byte DEK is
  generated and wrapped per write; the body is encrypted under the DEK. This
  makes key/nonce uniqueness structural: every write uses a fresh DEK and fresh
  nonces, so a key/nonce pair is never reused.

Salt is public (defeats precomputation; stored per vault). Nonces are public but
unique by construction. See `docs/VAULT_FORMAT.md` sections 2–5 for the exact
byte-level construction and AAD.

## 5. Key derivation and encryption flow

Summarized here; authoritative detail in `docs/VAULT_FORMAT.md` section 5.

1. Master password (hidden prompt; never argv) + random 16-byte salt →
   Argon2id → 32-byte KEK.
2. Random 32-byte DEK + random 12-byte wrap nonce + random 12-byte body nonce.
3. `wrapped_key = ChaCha20-Poly1305(KEK).encrypt(wrap_nonce, DEK, wrap_aad)`.
4. `body = ChaCha20-Poly1305(DEK).encrypt(body_nonce, payload, body_aad)`.
5. Unlock reconstructs the same AADs from the file's fixed layout, derives the
   KEK, unwraps the DEK, decrypts the body.

## 6. Storage format

Frozen in `docs/VAULT_FORMAT.md`. Key points: fixed binary header (no trusted
length fields), body = file remainder, AAD = exact header byte ranges binding
`format_version` and `vault_id`, canonical-JSON payload, single fixed Argon2id
profile and single AEAD. Strictly versioned; unknown versions refused.

## 7. Operations, persistence, and concurrency

- **init** (implemented): create a vault with no-clobber commit; refuse if the
  path exists.
- **unlock** (implemented): one-shot password verification (section 10 of the
  format spec); the vault is only read.
- **Persistence foundation (implemented):** `service.update_vault` applies a
  complete-payload transform under a sibling advisory lock, authenticates and
  validates before writing, and commits encrypted output with snapshot-checked
  atomic `os.replace`. Every replacement gets a fresh DEK and fresh wrap/body
  nonces. Creation remains separate and uses atomic no-clobber linking.
- **Entry CRUD commands (implemented):** `add`, `list`, `get`, `update`, and
  `delete` use the locked persistence service. IDs are stable and independent of
  titles; list output excludes fields, and get masks sensitive fields by default.
- **backup**: encrypted copy to a new unique path; never overwrite.
- **restore**: write a new vault to a new path; never overwrite.
- **Permissions**: directory `0700`, file `0600`; warn on open permissions.
- **Atomicity**: temp file in the same directory, `O_EXCL`, `fsync` file and
  directory, no-clobber `link` for new destinations, `os.replace` for updates.
- **Concurrency**: VaultForge updates serialize through an advisory sibling lock
  and verify a snapshot (device, inode, size, mtime_ns, SHA-256) before replace.
  This prevents lost updates among cooperating VaultForge writers and detects
  changes during an operation. Advisory locks are not enforced against arbitrary
  external writers or reliably honored on every network filesystem.
- **Corruption**: distinct errors for bad magic, unsupported version, invalid
  parameters, structural failure, and authentication failure.

## 8. Recovery and backups

- **Recovery disabled in v1.** No recovery key, escrow, security question,
  alternate path, or hidden slot. Losing the master password means the vault is
  **unrecoverable**; this is stated in the README and printed by `vault init`.
- Backups are encrypted snapshots. Backups taken **before** a password change
  require the **old** password; backups taken after require the new one.
- Restore never overwrites; the user must move the existing file aside first.
- A future opt-in recovery-key slot was considered and is deliberately **not**
  added now; it would require explicit approval and a separate design.

## 9. CLI and data model

```
# implemented
vaultforge vault init     [--vault PATH]
vaultforge vault unlock   [--vault PATH]
vaultforge vault list     [--vault PATH]
vaultforge vault add      --type T --title S [--vault PATH]
vaultforge vault get      ENTRY_ID [--vault PATH] [--reveal]
vaultforge vault update   ENTRY_ID [--vault PATH] [--title S] [--field NAME]
vaultforge vault delete   ENTRY_ID [--vault PATH]  # confirmation required
vaultforge vault backup   [--vault PATH] [--out PATH]
vaultforge vault restore  --backup PATH --out PATH
vaultforge vault validate [--vault PATH]
```

- Default vault path `~/.vaultforge/vault.vf`; directory created `0700`.
- Secret input: hidden prompt by default; `--from-file` for bulk fields; never
  via argv; environment variables are not used for the master password.
- Secret output: stdout only; prompts/warnings to stderr; masked unless
  `--reveal`; errors never include material.
- Data model: `Vault` (schema + entries); entries have a random 128-bit hex
  `id`, `type`, `title`, `tags`, timestamps, and typed `fields`.
- TOTP secrets are ordinary encrypted `totp` entries; no separate OTP store.

## 10. Risks and unresolved decisions

- Python cannot reliably zeroize memory; documented limitation, best-effort only.
- No rollback protection in v1.
- Entry count/size metadata is not hidden (no padding in v1).
- Per-invocation password prompts (no agent) affect ergonomics.
- Backup password policy (shared vs independent) deferred; v1 uses the vault
  password at backup time.
- Whether to add optional `mlock` best-effort hardening is deferred.

## 11. Implementation roadmap and acceptance criteria

Each milestone must pass its positive and negative acceptance tests before the
next begins. Negative tests are mandatory, not optional.

### M1 — Crypto primitives and serialization (implemented)
- Positive: same password/salt/params → same key; `decrypt(encrypt(x)) == x`;
  RFC 9106 Argon2id and RFC 8439 ChaCha20-Poly1305 vectors match; the golden v1
  fixture reproduces the exact header bytes and AADs.
- Negative: salt != 16 bytes, nonce != 12 bytes, DEK != 32 bytes, and
  out-of-range Argon2 parameters raise typed errors; no secret appears in any
  exception message.

### M2 — Init and unlock (implemented)
- Positive: init then unlock succeeds; header fields equal the frozen spec;
  file is exactly `122 + len(payload) + 16` bytes (163 for a fresh empty vault).
- Negative: **wrong password** → `AuthError` with the unified message; **existing
  destination** → `DestinationExistsError`, file untouched; a second `init`
  never overwrites.
- Implemented in `vault/service.py` (`initialize_vault`, `unlock_vault`,
  `empty_vault`, `default_vault_path`) and `vault/store.py` (bounded reads,
  atomic no-clobber writes, private permissions), exposed as
  `vaultforge vault init` / `vaultforge vault unlock`.
- CLI exit codes: `0` success, `1` authentication failure, `2` any other error
  (usage, missing/oversized file, existing destination, structural failure).

### M3 — Entry CRUD (implemented)
- Positive: login, TOTP, recovery-code, and note entries use the existing typed
  `fields` schema; IDs are random unique 128-bit hex values and do not change on
  rename; add/get/update/delete persist through `update_vault`.
- Negative: duplicate IDs, unknown IDs, invalid fields, and wrong passwords fail
  without committing; list omits all fields; get masks sensitive fields unless
  `--reveal`; delete requires interactive confirmation.
- No schema version or vault-format change was made. Duplicate IDs are now
  rejected as malformed payloads to keep ID-based operations unambiguous.

### M4 — Persistence, permissions, concurrency (safe persistence foundation implemented)
- Positive: file mode `0600`, directory `0700`; interrupted replacement (simulated
  failure before commit) leaves the original byte-for-byte intact. Store/service
  primitives implement secure temporary writes, locking, snapshot checks, and
  atomic replacement; M3 CRUD now uses this persistence path.
- Negative: **interrupted write** never yields a partial vault; **concurrent
  modification** during update → `ConcurrentModificationError`; open permissions
  produce a warning; temp files are removed on failure.

### M5 — Backup and restore
- Positive: backup creates a new decryptable file; restore creates a working
  vault at a new path.
- Negative: backup/restore onto an **existing destination** → refused; restoring
  over a vault requires the user to move it first; a backup made before a
  password change fails to open with the new password and succeeds with the old.

### M6 — Security and robustness tests
- **Tampered header** (each field: version, vault_id, KDF params, salt, nonces)
  → `AuthError` or `InvalidVaultError` as appropriate.
- **Tampered wrapped key** → `AuthError`.
- **Tampered body ciphertext** (flip each byte region) → `AuthError`.
- **Wrong password** → `AuthError` (never a crash, never a distinct "tamper"
  claim).
- **Malformed file**: too short, too long (> 16 MiB), bad magic, bad version,
  truncated, garbage → specific typed errors, no crash, no allocation blowup.
- **Excessive KDF parameters** (`m` past the cap, `t`/`p` past the cap, `m < 8p`)
  → `InvalidVaultError` **before Argon2id runs** (assert the KDF is not invoked).
- **Interrupted writes** and **existing destination files** for init/backup/
  restore.
- **Leakage**: no secret in stdout/stderr/logs/exceptions; an AST/`secrets`-spy
  test proving vault code uses `secrets`, never `random`.

### M7 — Focused security review
- Independent review of parsing, bounds, AAD construction, permission handling,
  and error wording; a small fuzz pass over the header parser.

## 12. Files to be created or modified (implementation phase)

Created: `src/vaultforge/vault/{__init__,crypto,format,payload,errors}.py` (M1),
`src/vaultforge/vault/{store,service}.py` (M2); and, in later milestones,
`model.py`; plus `tests/test_vault_{crypto,format,payload}.py` (M1),
`tests/test_vault_{store,service,cli}.py` (M2), and later
`test_vault_security.py`; this document and `docs/VAULT_FORMAT.md`.

Modified: `pyproject.toml` (add `cryptography`, extras, ruff notes),
`src/vaultforge/limits.py` (vault/KDF bounds), `src/vaultforge/cli.py` (register
the `vault` sub-app), and `README.md` (vault docs and the no-recovery warning).
