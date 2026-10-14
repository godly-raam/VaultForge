# VaultForge 0.1.0 Release Notes

**Status:** Initial alpha release. This release has functional and automated test
coverage, but it is not an independent security audit.

## Included

- Password, PIN, token, and EFF-wordlist passphrase generation using Python's
  `secrets` module.
- TOTP secret generation; code generation, verification, and provisioning URIs
  through the optional `pyotp` dependency.
- A local encrypted vault using the frozen v1 format: Argon2id, envelope
  encryption, and ChaCha20-Poly1305 authenticated encryption.
- Vault initialization, one-shot unlock verification, and encrypted persistent
  CRUD for login, TOTP, recovery-code, and note entries.
- Encrypted backup and restore. Backups and restores copy authenticated,
  validated encrypted vault bytes to new no-clobber destinations.
- Private temporary files, bounded reads, strict payload validation, and
  cooperating-writer locking for local vault updates.

## Important limitations

- **Master-password loss is unrecoverable.** There is no recovery key, escrow,
  reset path, password change command, or independent backup password.
- A backup requires the master password that protected its source when it was
  created. It remains encrypted, but is only as protected as its destination and
  any later copies.
- VaultForge writers coordinate with advisory sibling locks and snapshot checks.
  This does not control arbitrary external writers and is not a universal
  guarantee on network filesystems.
- New vault, backup, and restore destinations require filesystem hard-link
  support for atomic no-clobber publication. VaultForge fails closed when that
  primitive is unavailable.
- POSIX private-mode behavior is tested. Windows ACL, locking, symlink, and
  atomic-replacement behavior have not been verified; neither has macOS.
- Python cannot guarantee memory zeroization, and terminal output revealed with
  `vault get --reveal` may remain in scrollback or capture systems.
- The format does not hide vault file size, entry count, or entry-size metadata,
  and it has no rollback protection.

## Packaging and support

- Requires Python 3.10 or newer. CI is configured for Python 3.10–3.13 on
  Ubuntu; local release checks also ran on Python 3.14.7.
- Install with `pip install vaultforge`; add TOTP support with
  `pip install 'vaultforge[otp]'`.
- The package ships the `vaultforge` console script, bundled word list, and MIT
  license text.
