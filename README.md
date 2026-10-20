# VaultForge

A security-first, open-source CLI toolkit for generating secrets from your
terminal. VaultForge currently generates **passwords**, **PINs**, **tokens**,
and **memorable passphrases** using only the operating system's
cryptographically secure random number generator, generates and verifies
**time-based one-time passwords (TOTP)** using the optional
[`pyotp`](https://pyauth.github.io/pyotp/) library, and can create and open a
local **encrypted vault** (Argon2id + ChaCha20-Poly1305). Vault entry storage
is available for login, TOTP, recovery-code, and note entries; **vault recovery
is disabled** -- a lost master password cannot be recovered.

> VaultForge makes no claim that any generated value is "unbreakable". Strength
> depends on the size of the search space, how the secret is stored, and how it
> is used. See [Security decisions](#security-decisions).

## Installation

VaultForge is a standard `src/`-layout Python package. The declared floor is
Python 3.10 (`requires-python = ">=3.10"`), matching the current dependency
stack. Local checks in this environment ran on Python 3.14.7; CI is configured
to run Python 3.10-3.13 (see `.github/workflows/ci.yml`), but that workflow has
not been executed here.

Recommended, isolated installation:

```bash
# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install the package plus development tools (pytest, ruff, mypy)
python -m pip install -e ".[dev]"

# Optional: add TOTP support (pulls in PyOTP)
python -m pip install -e ".[otp]"
```

On systems with a managed Python (for example Debian/Ubuntu with PEP 668), use:

```bash
python3 -m pip install --break-system-packages -e ".[dev,otp]"
```

`otp generate`, `otp verify`, and `otp uri` need the `otp` extra. `otp secret`
works without it because it only generates random base32 material. If PyOTP is
missing, the commands that require it print an install hint instead of failing
obscurely. Either way, the `vaultforge` command is installed on your `PATH`.

## Usage

```bash
# Password: 32 characters, all classes (default), one line
vaultforge password --length 32

# Password without symbols or easily confused characters
vaultforge password --length 24 --no-symbols --exclude-ambiguous

# Generate three 20-character passwords
vaultforge password --length 20 --count 3

# PIN: exactly 6 digits, leading zeroes preserved
vaultforge pin --digits 6

# Token: 32 bytes (256 bits) of entropy, hex-encoded
vaultforge token --bytes 32

# Token: URL-safe base64 encoding instead of hex
vaultforge token --bytes 32 --encoding urlsafe

# Passphrase: 6 words separated by hyphens
vaultforge passphrase --words 6

# Passphrase with a space separator and capitalised words
vaultforge passphrase --words 5 --separator " " --capitalize

# TOTP: create a new base32 secret to enrol in your authenticator
vaultforge otp secret

# TOTP: current 6-digit code (the secret is read from a file, or you are prompted)
vaultforge otp generate --secret-file ~/.config/acme.secret

# TOTP: also show seconds until the code rolls over (written to stderr)
vaultforge otp generate --secret-file ~/.config/acme.secret --show-remaining

# TOTP: verify a code, tolerating one step (30s) of clock skew on each side
vaultforge otp verify --secret-file ~/.config/acme.secret --window 1

# TOTP: print an otpauth:// URI to paste into an authenticator app
vaultforge otp uri --secret-file ~/.config/acme.secret --name you@example.com --issuer ACME

# Vault: create a new encrypted vault at the default path (~/.vaultforge/vault.vf)
vaultforge vault init

# Vault: create it somewhere else
vaultforge vault init --vault /path/to/my.vault

# Vault: set a default path for vault commands; --vault still takes precedence
export VAULTFORGE_VAULT=/path/to/my.vault
vaultforge vault list

# Vault: verify the master password and open it (one-shot; no session is kept)
vaultforge vault unlock

# Vault: add a login (sensitive values are requested through hidden prompts)
vaultforge vault add --type login --title Example --vault /path/to/my.vault

# Vault: list non-sensitive entries in a readable table
vaultforge vault list --vault /path/to/my.vault

# Vault: request non-sensitive metadata as JSON for scripts
vaultforge vault list --json --vault /path/to/my.vault

# Vault: retrieve by stable entry ID (readable metadata and fields; sensitive values masked)
vaultforge vault get ENTRY_ID --vault /path/to/my.vault

# Vault: explicitly reveal sensitive fields
vaultforge vault get ENTRY_ID --reveal --vault /path/to/my.vault

# Vault: print only the current code from a stored TOTP entry
vaultforge vault totp ENTRY_ID --vault /path/to/my.vault

# Vault: rename an entry or change one field (values are prompted)
vaultforge vault update ENTRY_ID --title New-title --vault /path/to/my.vault

# Vault: delete after interactive confirmation
vaultforge vault delete ENTRY_ID --vault /path/to/my.vault

# Vault: create an authenticated encrypted backup (never overwrites)
vaultforge vault backup --vault /path/to/my.vault --out /path/to/backup.vf

# Vault: restore a backup to a new path (never overwrites or switches the active vault)
vaultforge vault restore --backup /path/to/backup.vf --out /path/to/restored.vf

# Show version
vaultforge --version
```

You can also invoke the module directly, which is useful when experimenting
without installing the console script:

```bash
python -m vaultforge password --length 16
```

### Command reference

| Command | Option | Default | Description |
|---|---|---|---|
| `password` | `--length`, `-l` | `16` | Total number of characters. |
| | `--lowercase/--no-lowercase` | on | Include `a-z`. |
| | `--uppercase/--no-uppercase` | on | Include `A-Z`. |
| | `--digits/--no-digits` | on | Include `0-9`. |
| | `--symbols/--no-symbols` | on | Include punctuation. |
| | `--exclude-ambiguous/--no-exclude-ambiguous` | off | Drop easily confused characters. |
| | `--count`, `-n` | `1` | How many to generate. |
| `pin` | `--digits`, `-d` | `6` | Number of digits. |
| | `--count`, `-n` | `1` | How many to generate. |
| `token` | `--bytes`, `-b` | `32` | Entropy in bytes. |
| | `--encoding`, `-e` | `hex` | `hex` or `urlsafe`. |
| | `--count`, `-n` | `1` | How many to generate. |
| `passphrase` | `--words`, `-w` | `6` | Number of words. |
| | `--separator`, `-s` | `-` | String between words. |
| | `--capitalize/--no-capitalize` | off | Capitalise each word. |
| | `--count`, `-n` | `1` | How many to generate. |
| `otp secret` | `--bytes`, `-b` | `20` | Secret entropy in bytes (20-128). |
| `otp generate` | `--secret-file` | prompt | File to read the base32 secret from. |
| | `--digits`, `-d` | `6` | Code length: 6, 7, or 8. |
| | `--period`, `-p` | `30` | Time step in seconds. |
| | `--algorithm`, `-a` | `sha1` | `sha1`, `sha256`, or `sha512`. |
| | `--at` | now | Generate for a POSIX timestamp. |
| | `--show-remaining` | off | Print seconds left in the window to stderr. |
| `otp verify` | `--secret-file` | prompt | File to read the base32 secret from. |
| | `--code-file` | prompt | File to read the code to check from. |
| | `--window`, `-w` | `0` | Accept this many steps of clock skew each side (0-10). |
| `otp uri` | `--secret-file` | prompt | File to read the base32 secret from. |
| | `--name`, `-n` | required | Account label (for example an email address). |
| | `--issuer`, `-i` | none | Optional service/issuer name. |
| `vault init` | `--vault` | `~/.vaultforge/vault.vf` | Create a new vault (refuses an existing file). |
| `vault unlock` | `--vault` | `~/.vaultforge/vault.vf` | Verify the master password once and exit. |
| `vault add` | `--type`, `--title`, `--vault` | required, required, default path | Add a typed entry; sensitive fields are prompted. |
| `vault list` | `--json`, `--vault` | table, default path | List stable IDs, titles, and types; use `--json` for metadata. |
| `vault get` | `ENTRY_ID`, `--reveal`, `--vault` | required, off, default path | Display readable metadata and fields; sensitive fields are masked unless revealed. |
| `vault totp` | `ENTRY_ID`, `--vault` | required, default path | Print only the current code from a stored TOTP entry. |
| `vault update` | `ENTRY_ID`, `--title`, `--field`, `--vault` | required, optional, optional, default path | Rename and/or update one prompted field; ID remains stable. |
| `vault delete` | `ENTRY_ID`, `--vault` | required, default path | Delete after interactive confirmation. |
| `vault backup` | `--vault`, `--out` | default path, generated sibling path | Authenticate and copy exact encrypted bytes to a new path. |
| `vault restore` | `--backup`, `--out` | required, required | Authenticate and copy backup bytes to a new path; never replaces the active vault. |

TOTP secrets and codes are **never** accepted as command-line arguments: argv
is visible in `ps` output and shell history. Supply them through a file, or
answer the hidden prompt. `otp verify` exits `0` when the code is valid and `1`
when it is not; usage errors exit `2`.

The `vault` commands read the master password from a hidden prompt (never from
the command line) and keep the prompt, warnings, and status messages on
**stderr**. Sensitive entry values are not accepted as command-line arguments;
entry fields are prompted for, and `get` masks password, TOTP secret, recovery
codes, notes, and note bodies unless `--reveal` is given; its output separates
metadata from fields. `vault totp ENTRY_ID` authenticates and prints only the
current code for a TOTP entry; it never prints the stored secret or rewrites the
vault. Listing prints stable IDs, titles, and types in a readable table; use
`vault list --json` for non-sensitive metadata. Delete requires interactive
confirmation. `vault init` refuses to
overwrite an existing file and writes it with `0600` permissions; it also warns
that **recovery is disabled** -- if the master password is lost, the vault cannot
be opened. `vault backup` authenticates and copies exact encrypted vault bytes to
a new path; it does not create a recovery path or a second password. `vault restore`
authenticates the backup before publishing exact encrypted bytes to a new path, and
refuses the active vault and detectable aliases. `vault unlock` verifies the
password once and exits; it keeps no session. Terminal output and Python memory
cannot be guaranteed secret. `vault` exit codes are `0` on success,
`1` for an authentication failure (a wrong password or a tampered/corrupted
vault, which are deliberately indistinguishable), and `2` for any other error
(usage, missing or oversized file, an existing destination, or corruption).

Generated secrets are printed to **stdout** and nowhere else. They are **never
written to a file or saved automatically**; if you want to keep one, redirect
or copy it yourself, and remember that shell history, scrollback, process
listings (`ps`), and terminal capture can all retain what you print.

All size parameters are capped to prevent an accidental typo from consuming
memory or CPU: password length and PIN length 1-4096, token entropy 1-4096
bytes, passphrase length 1-256 words, `--count` 1-10000, TOTP secret size 20-128
bytes, TOTP period 1-3600 seconds, and the verification window 0-10 steps. The
caps are enforced in the library and in the CLI.

## Security decisions

1. **Only `secrets`, never `random`.** Every secret is drawn from
   `secrets`, which reads from the OS CSPRNG (`os.urandom` /
   `getrandom`). The `random` module implements a Mersenne Twister whose state
   can be reconstructed from a small number of outputs and must never produce
   passwords, PINs, or tokens. A test parses the source with `ast` to prove
   the module neither imports nor exposes `random`.

2. **Character requirements without predictable patterns (with a documented
   caveat).** When a class (letters/digits/symbols) is enabled, VaultForge
   guarantees at least one character from that class, fills the remainder from
   the combined alphabet, and then performs a secure Fisher-Yates shuffle using
   `secrets.randbelow`. This removes the classic bug where the required digit
   always sits in a fixed position. **Caveat:** this construction is *not* a
   uniform sample over the set of valid passwords. Forcing exactly the minimum
   of each class before filling over-weights strings that contain only the
   minimum of each class. The shuffle fixes positional ordering, not this
   distributional bias. At realistic lengths the effect is negligible, and the
   search space remains astronomically large, but it is stated here rather than
   hidden.

3. **Validate before generating.** Impossible configurations (zero length, no
   enabled classes, or a length smaller than the number of required classes)
   are rejected with an actionable error before any randomness is consumed.

4. **PINs preserve leading zeroes.** `generate_pin` returns a zero-padded
   *string* rather than an integer, so `007` stays `007`. Tests prove this
   deterministically with a stubbed RNG and statistically with real output.

5. **Tokens expose exact entropy.** `--bytes` is the number of random bytes,
   not the output length. Hex output is `2 * bytes` characters; URL-safe base64
   output has a variable length but the decoded payload is exactly `bytes`.

6. **No secrets in logs.** The library never logs or writes generated values.
   Only the CLI writes them, and only to stdout.

7. **Password entropy is not a certificate.** `length * log2(alphabet)` is an
   **upper bound** on the entropy of the constrained generator, not an exact
   figure, because one character per enabled class is drawn from that class's
   smaller alphabet and the construction is biased (see point 2). It also says
   nothing about server-side hashing, reuse, or phishing. Treat length as one
   factor, not a promise.

8. **Passphrase entropy is explicit, and output is constrained.** Words are
   chosen uniformly from a bundled 7,772-word list, giving
   `log2(7772) ≈ 12.92` bits per word, or about **77.5 bits** for the default 6
   words (assuming the attacker knows the list -- Kerckhoffs's principle -- and
   that words are independent). A separator containing control characters is
   rejected, since it would corrupt line-oriented output.

9. **A random PIN is not a TOTP.** `vaultforge pin` produces a fixed, random
   numeric code (for example a device PIN or a fixed-width code). It is
   **not** a time-based one-time password: it does not derive codes from a
   shared secret and the current time, it does not change every 30 seconds, it
   cannot be verified by an authenticator app, and it is not an MFA factor. For
   a real TOTP, use the `otp` commands (see decision 11).

10. **Generated secrets are not persisted; the vault is opt-in and encrypted.**
    VaultForge never writes generated passwords, PINs, tokens, or passphrases to
    disk, logs, or telemetry; their output goes to stdout only. The encrypted
    vault is the one place the tool writes secrets, and only the data *you*
    choose to place in it (the M2 commands create and open an empty vault; entry
    storage comes later). TOTP secrets are the other exception only in that
    *you* may choose to hand VaultForge a file to read; it writes nothing back.

11. **The vault uses one vetted KDF and one vetted AEAD, never hand-rolled
    crypto.** Argon2id (RFC 9106) derives a key-encryption key from the master
    password and a per-vault random salt; ChaCha20-Poly1305 (RFC 8439) wraps a
    per-write data key and encrypts the body. Both come from the `cryptography`
    library and are checked against the RFC test vectors. The format is frozen at
    v1 with no algorithm agility: there is one Argon2id profile (m=65536 KiB,
    t=3, p=1) and one AEAD, and a file that declares anything else is rejected.

12. **The vault never clobbers and never needs the password on the command
    line.** `vault init` writes to a private temp file and commits it with an
    atomic no-clobber operation, refusing (and leaving untouched) any existing
    destination; the directory is created `0700` and the file `0600`. The master
    password is read from a hidden prompt, never argv or an environment
    variable, and prompts, warnings, and status go to stderr. A wrong password
    and a tampered vault deliberately produce the *same* error, because the
    Poly1305 tag cannot tell them apart.

13. **TOTP is delegated to a maintained library, not hand-rolled.** `otp`
    commands wrap [`pyotp`](https://pyauth.github.io/pyotp/) rather than
    re-implementing HMAC and code truncation. The implementation is checked
    against the RFC 6238 SHA-1, SHA-256, and SHA-512 known-answer vectors, so it
    interoperates with standard authenticator apps. `sha1` is the default because
    it is what authenticator apps assume; SHA-1 is *not* a weakness here, since
    HMAC-SHA-1 is unaffected by the collision attacks that retired SHA-1 for
    digital signatures. Choosing another algorithm is a compatibility decision,
    not a security upgrade.

14. **TOTP time is normalised to UTC.** Every timestamp is converted to a
    timezone-aware UTC datetime before being turned into a counter value. Passed
    as a naive local time, the same integer could map to different codes on
    machines in different timezones or across a DST transition. Tests pass
    aware/naive/epoch inputs and confirm they agree.

15. **Secret input avoids argv, and comparison is constant-time.** TOTP secrets
    and codes are read from a file or a hidden prompt, never a command-line
    argument, because argv leaks through `ps` and shell history. Verification
    uses PyOTP's constant-time comparison via `hmac.compare_digest`, so a
    wrong-but-close code does not reveal itself through timing.

16. **The optional dependency stays optional.** `pyotp` is imported lazily, so
    the other commands work without it. Only the `otp` commands raise a clear
    error suggesting `pip install 'vaultforge[otp]'`.

## Project structure

```
pyproject.toml                      Build metadata, deps, tool config, console script
README.md
.github/workflows/ci.yml            Lint, format-check, type-check, test (3.10-3.13)
src/vaultforge/
  __init__.py                       Version and package docstring
  __main__.py                       Enables `python -m vaultforge`
  cli.py                            Typer CLI: parse, call, print
  generators.py                     Pure generation logic (secrets only)
  limits.py                         Documented upper bounds for parameters
  otp.py                            TOTP library (lazy PyOTP wrapper)
  policy.py                         PasswordPolicy dataclass + validation
  wordlist.py                       Cached, validated word-list loader
  data/wordlist.txt                 Bundled word list (see attribution)
  vault/                            Encrypted-vault internals (format v1)
    __init__.py                     Package docstring
    errors.py                       Exception hierarchy
    crypto.py                       Argon2id + ChaCha20-Poly1305 primitives
    format.py                       v1 container layout, AAD, header parsing
    payload.py                      Canonical JSON payload + strict schema
    store.py                        Bounded reads, atomic no-clobber writes
    service.py                      initialize_vault / unlock_vault operations
tests/
  test_policy.py                    Policy and validation rules
  test_generators.py                Passwords, PINs, tokens, boundaries
  test_passphrase.py                Passphrases and word list
  test_randomness.py                Asserts `secrets` usage, no `random`
  test_cli.py                       End-to-end CLI behaviour and exit codes
  test_limits.py                    Parameter caps and separator validation
  test_secret_hygiene.py            No leakage via stderr or logging
  test_otp.py                       TOTP validation, verification, helpers
  test_otp_vectors.py               RFC 6238 known-answer vectors
  test_otp_cli.py                   `otp` subcommands end to end
  test_vault_crypto.py              Argon2id/ChaCha20-Poly1305 vectors, validation
  test_vault_format.py              Container layout, golden fixture, rejections
  test_vault_payload.py             Canonical JSON serialization and schema
  test_vault_store.py               Bounded reads, atomic/no-clobber writes, perms
  test_vault_service.py             Init/unlock round-trips and tamper detection
  test_vault_cli.py                 `vault` subcommands end to end
  test_packaging.py                 Metadata, entry point, module invocation
```

The core (`generators.py`, `policy.py`, `limits.py`) has no CLI or I/O concerns,
so it can be reused as a library and tested without spawning a process. `otp.py`
keeps the same separation and isolates the optional dependency, and the
`vault/` package separates bytes (`crypto.py`, `format.py`, `payload.py`) from
storage (`store.py`) and operations (`service.py`).

## Development and quality checks

Run everything from the repository root after `pip install -e ".[dev]"`:

```bash
# Automated tests
python3 -m pytest

# Verbose test output
python3 -m pytest -v

# Lint (includes security-oriented flake8-bandit rules)
ruff check .

# Check formatting without modifying files
ruff format --check .

# Static type checking (source only)
python3 -m mypy
```

To apply formatting automatically:

```bash
ruff format .
```

### Current verified results

In this environment (Python 3.11.2, ruff 0.17.0, mypy 2.4.0):

```
329 passed in 9.09s        # pytest
All checks passed!        # ruff check .
35 files already formatted  # ruff format --check .
Success: no issues found in 15 source files  # mypy
```

The suite covers output lengths, character-class constraints, PIN leading
zeroes, valid and invalid arguments, impossible password configurations, token
encoding and byte lengths, passphrase word counts and separators, parameter
caps, CLI exit codes, secret non-leakage (stderr and logging), packaging, TOTP
against the RFC 6238 SHA-1/SHA-256/SHA-512 known-answer vectors, and the vault
against the RFC 8439 ChaCha20-Poly1305 and RFC 9106 Argon2id vectors plus the
init/unlock and tamper-detection paths.
Outputs are never asserted to be pairwise distinct; variety is checked with a
threshold that is statistically safe rather than flaky, and the use of the
correct cryptographic APIs is verified directly (AST inspection and RNG spies).
These are functional tests, not a security audit, formal verification, or
statistical validation.

## Dependencies

- Runtime: [`typer`](https://typer.tiangolo.com/) (CLI parsing; pulls in Click),
  and [`cryptography`](https://cryptography.io/) (Argon2id and
  ChaCha20-Poly1305, used by the `vault` commands).
- Optional (`.[otp]`): [`pyotp`](https://pyauth.github.io/pyotp/) (TOTP). Only
  needed for the `otp` commands.
- Development (`.[dev]`): [`pytest`](https://pytest.org/) (tests),
  [`ruff`](https://docs.astral.sh/ruff/) (lint + format),
  [`mypy`](https://mypy-lang.org/) (static types), plus `pyotp`.

Passwords, PINs, tokens, and passphrases are generated entirely from the Python
standard library's `secrets` module, with no third-party generation code. TOTP
is delegated to `pyotp`, and the encrypted vault delegates Argon2id and
ChaCha20-Poly1305 to `cryptography`; neither rolls its own cryptography or uses
the `random` module.

## Known limitations

- **Constrained password sampling is biased.** Guaranteeing one character per
  class before filling is not a uniform sample over valid passwords (see
  Security decision 2). Practical impact is negligible at realistic lengths.
- **No custom alphabets.** The symbol set is fixed to `string.punctuation`; you
  cannot supply your own character set, nor does the tool restrict output to
  URL-safe or non-shell-special characters.
- **Only Python 3.11 has actually been tested here.** The floor is declared as
  3.10 (matching the dependency stack) and a CI matrix targets 3.10-3.13, but
  those runs have not happened in this environment.
- **`--exclude-ambiguous` replaces characters, it does not shrink length.** The
  length is always exact; excluding characters only shrinks the alphabet.
- **Not a password manager.** Generated secrets are not stored, scored against
  breach corpora, or checked against site-specific policies.
- **TOTP is TOTP only.** VaultForge implements time-based codes (RFC 6238), not
  counter-based HOTP (RFC 4226), and it does not render QR codes -- use the
  `otp uri` output with your own QR tool if you need one.
- **TOTP secrets are not stored or encrypted.** VaultForge can generate a secret
  and derive codes from one you provide, but protecting the secret at rest is up
  to you. A TOTP secret is a bearer credential: anyone who reads it can generate
  valid codes.
- **Vault recovery is disabled.** Login, TOTP, recovery-code, and note entries
  can be added, listed, retrieved, updated, and deleted; encrypted backups can be
  created and restored only to a new path. There is no recovery key or reset: lose
  the master password and the vault cannot be opened, including from a backup.
  Unlocking verifies the password but keeps no session. The v1 format does not pad
  entry data, so the number and sizes of entries are not hidden.
- **The vault requires a filesystem that supports hard links.** A new vault is
  published with `os.link`, which fails atomically if the destination exists;
  this is how `vault init` guarantees it never overwrites an existing file. On a
  filesystem without hard links (for example FAT/exFAT or some network mounts)
  `vault init` fails with an actionable error rather than risk leaving a partial
  vault. `vault unlock` is unaffected. Updates use atomic replacement and an
  advisory sibling lock; this coordinates VaultForge writers but does not
  control arbitrary external writers or guarantee safety on every network
  filesystem.

## Word list attribution

`src/vaultforge/data/wordlist.txt` is derived from the **EFF Large Wordlist for
Passphrases** (originally generated by the Diceware method), published by the
Electronic Frontier Foundation under the
[Creative Commons Attribution 3.0 US license](https://creativecommons.org/licenses/by/3.0/us/).
Four hyphenated entries were removed so that one word always maps to one token.
The upstream list contains 7,776 words; the bundled list contains 7,772.

## Scope

This milestone covers secure generation and TOTP. It deliberately does **not**
include an encrypted vault, persistent or encrypted storage of generated
secrets, QR rendering, HOTP, file encryption, post-quantum cryptography, network
services, or user authentication. Those belong to later milestones.

## License

MIT (see `pyproject.toml`). The bundled word list remains under CC BY 3.0 US as
noted above.
