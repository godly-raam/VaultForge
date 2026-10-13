# VaultForge Vault Format — Specification v1

Status: **FROZEN and approved; v1 primitives (M1) and init/unlock (M2)
implemented**. This document is the single source of truth for the on-disk vault
format. The primitives, header layout, AAD construction, and payload
serialization are implemented in `src/vaultforge/vault/` (`crypto.py`,
`format.py`, `payload.py`), and file creation and one-shot unlock in
`store.py` and `service.py`. The remaining milestones follow the roadmap in
`docs/VAULT_DESIGN.md`.

Scope: local, single-user, offline encrypted vault. No network, no server, no
multi-user, no recovery mechanism.

---

## 1. Conventions

- All multi-byte integers are **unsigned big-endian**.
- All byte offsets are zero-based and inclusive-exclusive (`[start, end)`).
- Cryptographic random values come from the OS CSPRNG via Python `secrets`
  (`secrets.token_bytes`). The `random` module is never used.
- The word **"must"** denotes a hard requirement; a v1 reader that cannot satisfy
  it must reject the file rather than guess.

## 2. Selected primitives (single, fixed — no agility)

v1 defines exactly one KDF and exactly one AEAD. There are no algorithm
identifiers and no per-vault choices in the format.

| Role | Primitive | Parameters |
|---|---|---|
| Key derivation | **Argon2id** (RFC 9106) | memory = 65,536 KiB, iterations = 3, lanes = 1, output = 32 bytes |
| Key wrapping (DEK) | **ChaCha20-Poly1305** | 256-bit key, 96-bit nonce, 128-bit tag |
| Body encryption | **ChaCha20-Poly1305** | 256-bit key, 96-bit nonce, 128-bit tag |

Rationale is in `docs/VAULT_DESIGN.md` (section 4). A future format version may
change these; v1 files are always written with the values above.

## 3. Container layout

A v1 vault is a single file with a fixed-size header followed by the encrypted
body. There are **no embedded length fields** to trust: the body is exactly the
remainder of the file, and its length is derived from the file size.

```
offset  size  field
------  ----  -------------------------------------------------------------
   0      5   magic            = 0x56 0x4C 0x54 0x46 0x47  ("VLTFG")
   5      1   format_version   = 0x01
   6     16   vault_id         random, per vault
  22      4   argon2_memory_kib (uint32 BE)
  26      4   argon2_iterations (uint32 BE)
  30      4   argon2_lanes      (uint32 BE)
  34     16   argon2_salt       random, per vault
  50     12   wrap_nonce        random, per write
  62     12   body_nonce        random, per write
  74     48   wrapped_key       ChaCha20-Poly1305(KEK, wrap_nonce, DEK, wrap_aad)
 122    var   body_ciphertext   ChaCha20-Poly1305(DEK, body_nonce, payload, body_aad)
```

Derived constants:

```
HEADER_PREFIX_LEN = 74    # bytes [0, 74)   -- fixed cleartext prefix
WRAPPED_KEY_LEN   = 48    # 32-byte DEK ciphertext + 16-byte tag
HEADER_LEN        = 122   # bytes [0, 122)  -- prefix + wrapped_key
TAG_LEN           = 16
SALT_LEN          = 16
VAULT_ID_LEN      = 16
NONCE_LEN         = 12
DEK_LEN           = 32
MIN_FILE_LEN      = HEADER_LEN + TAG_LEN = 138
MAX_FILE_LEN      = 16 * 1024 * 1024       # 16 MiB
```

- `wrapped_key` is the AEAD encryption of the 32-byte DEK, so its length is
  always exactly 48 bytes (32 + 16 tag) and it sits at a fixed offset.
- `body_ciphertext` is the AEAD encryption of the canonical payload; its length
  is `len(payload) + 16`.

## 4. Exact authenticated-data (AAD) construction

Both AEAD operations authenticate a slice of the file itself. Define:

```
wrap_aad = file_bytes[0:74]      # magic .. body_nonce, EXCLUDING wrapped_key
body_aad = file_bytes[0:122]     # magic .. wrapped_key (the whole header)
```

- **DEK wrap:** `wrapped_key = ChaCha20Poly1305(KEK).encrypt(wrap_nonce, DEK, wrap_aad)`.
  This binds the format version, vault identity, KDF parameters, salt, and both
  nonces to the wrapped key. A reader reconstructs `wrap_aad` from the first 74
  bytes it just read.
- **Body:** `body_ciphertext = ChaCha20Poly1305(DEK).encrypt(body_nonce, payload, body_aad)`.
  This binds the entire header *including the wrapped key bytes* to the body, so
  the body cannot be separated from the exact DEK that produced it, nor can any
  header field change without invalidating the tag.

The wrap AAD cannot include `wrapped_key` itself (that would be circular); the
body AAD closes that gap by authenticating `wrapped_key` together with the body.

**vault identity and version binding:** `vault_id` (16 random bytes) and
`format_version` are inside `[0, 74)`, and therefore authenticated by *both*
tags. A file from a different vault, or re-labelled with a different version,
fails authentication.

## 5. Key derivation and encryption flow

### 5.1 Initialize (write)
1. Collect the master password (hidden prompt; never from argv). Generate
   `argon2_salt` (16) and `vault_id` (16) from `secrets.token_bytes`.
2. `KEK = Argon2id(salt=argon2_salt, length=32, memory_cost=65536,
   iterations=3, lanes=1, ad=None, secret=None).derive(password_utf8)`.
3. `DEK = secrets.token_bytes(32)`; generate `wrap_nonce` (12) and
   `body_nonce` (12).
4. Serialize the payload (section 6), then compute `wrap_aad`, `body_aad`
   exactly as in section 4.
5. `wrapped_key = ChaCha20Poly1305(KEK).encrypt(wrap_nonce, DEK, wrap_aad)`.
6. `body_ciphertext = ChaCha20Poly1305(DEK).encrypt(body_nonce, payload, body_aad)`.
7. Write the file atomically with no-clobber semantics (section 8).

### 5.2 Unlock (read)
1. Reject files outside `[138, 16 MiB]` before reading the whole file.
2. Read the whole file (bounded), parse and range-check the header (section 7)
   **before** running Argon2id.
3. `KEK = Argon2id(...)` using the stored salt and parameters.
4. `DEK = ChaCha20Poly1305(KEK).decrypt(wrap_nonce, wrapped_key, wrap_aad)`.
   A failure here is `AuthError`.
5. `payload = ChaCha20Poly1305(DEK).decrypt(body_nonce, body_ciphertext, body_aad)`.
   A failure here is `AuthError`.
6. Parse the payload JSON and validate the schema.

`AuthError` is deliberately **one** error: "wrong master password, or the vault
is corrupted or has been tampered with." The tags cannot distinguish the two
causes, so the tool must never claim it knows which occurred.

### 5.3 Password change (write, full rewrite)
Changing the master password is a **full re-encryption**, written atomically:
1. Verify the old password (unwrap DEK, verify body tag).
2. Generate a **new** `argon2_salt`, new `KEK`, new `DEK`, new `wrap_nonce`,
   and new `body_nonce`.
3. Re-encrypt the payload under the new DEK, wrap the new DEK under the new KEK,
   and replace the vault atomically.
Consequences (must be documented in CLI output):
- Existing **backups keep their old password**; they are snapshots and are not
  re-keyed when the vault password changes.
- After a password change, all new backups must be made with the new password.

## 6. Payload schema (inside the AEAD)

The decrypted body is canonical JSON (UTF-8):

- Written as `json.dumps(obj, sort_keys=True, separators=(",", ":"),
  ensure_ascii=True, allow_nan=False).encode("utf-8")`.
- No floating-point numbers are permitted anywhere. Timestamps are integers
  (Unix seconds, UTC) or ISO-8601 strings, chosen once and used consistently.

```
{
  "schema": 1,
  "entries": [
    {
      "id": "<32 hex chars = 128-bit random>",
      "type": "login" | "totp" | "recovery" | "note",
      "title": "string",
      "tags": ["string", ...],
      "created_at": <int>,
      "updated_at": <int>,
      "fields": { ... type-specific ... }
    }
  ]
}
```

Type-specific `fields`:
- `login`: `username`, `password`, optional `url`, optional `notes`.
- `totp`: `secret` (base32), `digits` (6/7/8), `period` (int), `algorithm`
  (`sha1`|`sha256`|`sha512`), optional `issuer`, optional `account`.
- `recovery`: `codes` (list of strings), optional `notes`.
- `note`: `body` (string).

TOTP secrets are ordinary encrypted fields. There is **no** separate OTP store.

## 7. Strict parsing and resource limits (all checks precede the KDF)

A reader executes checks in this order and rejects at the first failure:

1. **Size gate (no allocation beyond the cap):** file size must be in
   `[138, 16 MiB]`. Check via `os.stat` before reading; read with a hard cap.
2. **Magic:** bytes `[0, 5)` must equal `b"VLTFG"`.
3. **Version:** byte `[5, 6)` must equal `0x01`. Other values →
   `UnsupportedVersionError`.
4. **KDF bounds (before Argon2id):**
   - `argon2_memory_kib` in `[8, 1,048,576]` and `>= 8 * argon2_lanes`
   - `argon2_iterations` in `[1, 10]`
   - `argon2_lanes` in `[1, 4]`
   Any violation → `InvalidVaultError` (prevents KDF-based DoS/OOM).
5. **v1 profile check:** a v1 reader requires the written profile to be the v1
   profile (`m=65536`, `t=3`, `p=1`). A different (but in-range) profile is
   treated as an unsupported vault in v1, keeping the format unambiguous.
6. **Fixed-length fields:** salt, nonces, and `wrapped_key` must occupy their
   fixed sizes (guaranteed by the size gate; asserted defensively).
7. **Then, and only then:** derive the KEK, unwrap, decrypt, and parse JSON.
8. **Payload limits (after decrypt, before allocation-heavy work):**
   entries ≤ 100,000; total payload ≤ 16 MiB; per-field string lengths capped;
   `id` must be 32 lowercase hex chars; `type` must be a known value; JSON depth
   bounded; unknown top-level keys rejected.

No `pickle`, `eval`, `exec`, or any code-executing deserialization is used
anywhere. Only `json.loads`.

## 8. Persistence, atomicity, and safe destinations

### 8.1 File permissions
- Vault directory: `0700`. Vault file: `0600`.
- On unlock, if group/other permission bits are set, emit a warning to stderr
  (do not silently proceed as if secure). Windows ACL limitations are documented.

### 8.2 Atomic write with no-clobber (init, backup, restore)
1. Create a temp file in the **same directory** as the destination using
   `os.open(tmp, O_CREAT|O_EXCL|O_WRONLY, 0o600)`.
2. Write the full buffer; `flush`; `os.fsync(fd)`; close.
3. Commit without overwriting using an atomic no-clobber primitive:
   `os.link(tmp, target)` — this raises `FileExistsError` if `target` already
   exists, atomically. (Fallback where hardlinks are unavailable:
   `os.open(target, O_CREAT|O_EXCL|O_WRONLY)` as a reservation, then rename.)
4. `os.fsync` the directory; unlink the temp file.

If the destination exists at step 3, the operation fails with
`DestinationExistsError` and the temp file is removed. **No flag may cause a
vault or backup to be overwritten silently.** The user must choose a different
path.

### 8.3 In-place update (add/update/delete) — intentional, not a clobber
1. Acquire an advisory lock on the vault (`fcntl.flock` POSIX / `msvcrt` on
   Windows) via a sibling `.lock` file.
2. Record the pre-image identity (size, mtime_ns, and a SHA-256 of the bytes)
   as a compare-and-swap token.
3. Decrypt, mutate the payload, re-encrypt with a **fresh DEK and fresh nonces**.
4. Write to a temp file in the same directory, `fsync`, then re-check the CAS
   token. If the vault changed since step 2, abort with `ConcurrentModificationError`
   and remove the temp file.
5. `os.replace(tmp, target)` (atomic on POSIX and Windows), then fsync the
   directory.

Locking is advisory and may not be honored on all network filesystems; the CAS
check is the backstop that prevents lost updates. `os.replace` here overwrites
the user's *own* named vault as the explicit result of an edit they requested —
this is not the prohibited "silent overwrite of a destination."

### 8.4 Race-condition review
- Temp files are created with `O_EXCL` in the destination directory, so two
  concurrent writers cannot share a temp name.
- No-clobber commit (`link`/`O_EXCL`) means two concurrent `init`/`backup` calls
  targeting the same path cannot both succeed.
- The CAS check ensures an update cannot overwrite a vault that changed after it
  was read.
- `os.replace` is atomic, so readers never observe a partially written file.

## 9. Backup and restore

- **Backup (`vault backup --out PATH`)**: writes an encrypted copy of the vault
  to a **new** path using section 8.2 (no-clobber). If `--out` is omitted, a
  unique name is generated (`vault-YYYYMMDDTHHMMSSZ-<4 random hex>.vf`). The
  backup uses the **same** master password as the vault at the time it is made.
- **After a password change**, previous backups remain decryptable only with the
  **old** password. This is documented and surfaced by `vault backup`.
- **Restore (`vault restore --backup B --out PATH`)**: decrypts `B` and writes a
  new vault to `PATH` using section 8.2 (no-clobber). If `PATH` exists, the
  operation fails with `DestinationExistsError`; restoring over an existing vault
  is never done automatically. The user must move or rename the existing file
  themselves first.

## 10. Locking and `unlock` semantics (v1)

- **No persistent session exists in v1.** No derived key, DEK, or decrypted
  payload is ever written to disk or cached between processes.
- `vaultforge vault unlock` is a **one-shot verification**: it prompts for the
  password, performs the full read path, prints `ok` to stderr, and exits `0`.
  On failure it prints the unified `AuthError` message and exits `1`.
- Every other command prompts for the password on each invocation. A persistent
  session manager (agent) is explicitly **out of scope** and requires a separate
  design and approval.

## 11. Recovery policy (v1)

- **Recovery is disabled.** There is no recovery key, no escrow, no security
  question, no alternate or hidden decryption path, and no key stored on the
  user's behalf.
- If the master password is lost, the vault is **unrecoverable**. This is stated
  in the README and printed by `vault init`.
- The only mitigation is an encrypted backup the user makes and keeps, which
  still requires the correct password.

## 12. Error taxonomy

| Condition | Error | Notes |
|---|---|---|
| Size out of range | `InvalidVaultError` | Before allocation. |
| Bad magic / version | `NotAVaultError` / `UnsupportedVersionError` | Distinct messages. |
| KDF params out of bounds, or non-v1 profile | `InvalidVaultError` | Before Argon2id. |
| Wrong password / tampered wrap or body | `AuthError` | Single unified message. |
| Valid crypto but malformed payload JSON/schema | `CorruptPayloadError` | After successful decrypt. |
| Destination exists (init/backup/restore) | `DestinationExistsError` | No overwrite. |
| Concurrent modification during update | `ConcurrentModificationError` | CAS failure. |

No error message, log record, or traceback may contain a secret, the master
password, the KEK/DEK, or decrypted payload bytes.

## 13. Versioning and migration

- `format_version` is authenticated in both tags. A file declaring an unknown
  version is refused with `UnsupportedVersionError` (never guessed at).
- Migration, when it exists, reads the old vault and writes a **new** file to a
  user-chosen path (or a timestamped sibling) via section 8.2. The original is
  left byte-for-byte intact. Migrations never overwrite.
- Because v1 stores its KDF parameters and binds them into the tags, a future
  version can raise defaults without breaking v1 readers of v1 files.

## 14. Test vectors and differential checks

- Argon2id: RFC 9106 vectors (and independent vectors) for the fixed profile,
  verified against the `cryptography` implementation.
- ChaCha20-Poly1305: RFC 8439 AEAD vectors.
- A golden v1 vault fixture with fixed salt, vault_id, DEK, and nonces to pin
  the exact byte layout and AAD construction; any format change must update this
  fixture deliberately.

M1 implements the first three as `tests/test_vault_crypto.py` (RFC 9106 §5.3 and
RFC 8439 §2.8.2 known-answer vectors), `tests/test_vault_format.py` (golden
74/122-byte fixtures and every ordered rejection), and
`tests/test_vault_payload.py` (canonical JSON, strict parsing, schema limits).
