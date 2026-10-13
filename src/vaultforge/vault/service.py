"""Library operations for creating and opening a vault (format v1).

These are the two operations the ``vaultforge vault`` commands are built on, and
they are usable on their own as a library:

* :func:`initialize_vault` -- write a brand-new, empty vault to a new path.
* :func:`unlock_vault` -- verify a vault and return its fully validated payload.

Both take the master password as already-encoded UTF-8 ``bytes`` and never log,
print, or cache it. Key material (the KEK, the DEK) and the decrypted payload
are held in ``bytearray`` buffers and overwritten on the way out; this is
best-effort only, because Python cannot guarantee that a value was not copied
elsewhere in memory.

Nothing here invents format fields: the exact byte layout and authenticated-data
construction are the frozen ones from :mod:`vaultforge.vault.format` and
:mod:`vaultforge.vault.crypto`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .crypto import (
    decrypt_body,
    derive_kek,
    encrypt_body,
    generate_dek,
    generate_nonce,
    generate_salt,
    unwrap_dek,
    wipe,
    wrap_dek,
)
from .errors import DestinationExistsError
from .format import (
    HEADER_LEN,
    VaultHeader,
    assemble_header,
    body_aad,
    build_header_prefix,
    generate_vault_id,
    parse_header,
    wrap_aad,
)
from .payload import SCHEMA_VERSION, deserialize_payload, serialize_payload
from .store import ensure_parent_directory, read_vault_bytes, write_new_vault

__all__ = [
    "default_vault_path",
    "empty_vault",
    "initialize_vault",
    "unlock_vault",
]

DEFAULT_VAULT_DIRNAME = ".vaultforge"
DEFAULT_VAULT_FILENAME = "vault.vf"


def default_vault_path() -> Path:
    """Return the default vault location: ``~/.vaultforge/vault.vf``."""
    return Path.home() / DEFAULT_VAULT_DIRNAME / DEFAULT_VAULT_FILENAME


def empty_vault() -> dict[str, Any]:
    """Return a fresh, empty vault payload (schema v1, no entries)."""
    return {"schema": SCHEMA_VERSION, "entries": []}


def initialize_vault(path: Path, password: bytes) -> VaultHeader:
    """Create a new, empty v1 vault at ``path`` and return its header.

    Refuses to touch an existing destination (fast-failed here, and enforced
    atomically at commit time). ``password`` must be the UTF-8 encoding of the
    master password. The returned header contains no secret material.
    """
    ensure_parent_directory(path)
    if os.path.lexists(path):
        raise DestinationExistsError(f"refusing to overwrite existing file: {path}")

    vault_id = generate_vault_id()
    salt = generate_salt()
    wrap_nonce = generate_nonce()
    body_nonce = generate_nonce()
    plaintext = serialize_payload(empty_vault())

    kek = bytearray(derive_kek(password, salt))
    dek = bytearray(generate_dek())
    try:
        prefix = build_header_prefix(
            vault_id=vault_id,
            salt=salt,
            wrap_nonce=wrap_nonce,
            body_nonce=body_nonce,
        )
        wrapped_key = wrap_dek(kek, wrap_nonce, dek, aad=wrap_aad(prefix))
        header = assemble_header(prefix, wrapped_key)
        body = encrypt_body(dek, body_nonce, plaintext, aad=body_aad(header))
        blob = header + body
        write_new_vault(path, blob)
    finally:
        wipe(kek)
        wipe(dek)

    return parse_header(blob)


def unlock_vault(path: Path, password: bytes) -> dict[str, Any]:
    """Verify ``path`` and return its validated payload, or raise.

    The header is checked (size, magic, version, KDF bounds and the pinned v1
    profile) before any key derivation. A wrong password and any tampering both
    surface as the single :class:`~vaultforge.vault.errors.AuthError`; a payload
    that decrypts but is malformed surfaces as
    :class:`~vaultforge.vault.errors.CorruptPayloadError`. The vault is only
    read, never modified, and no key or payload survives the call.
    """
    data = read_vault_bytes(path)
    header = parse_header(data)

    wrap_data = wrap_aad(data)
    body_data = body_aad(data)
    body_ciphertext = data[HEADER_LEN:]

    kek = bytearray()
    dek = bytearray()
    plaintext = bytearray()
    try:
        kek = bytearray(derive_kek(password, header.salt))
        dek = bytearray(unwrap_dek(kek, header.wrap_nonce, header.wrapped_key, aad=wrap_data))
        plaintext = bytearray(decrypt_body(dek, header.body_nonce, body_ciphertext, aad=body_data))
        return deserialize_payload(bytes(plaintext))
    finally:
        wipe(kek)
        wipe(dek)
        wipe(plaintext)
