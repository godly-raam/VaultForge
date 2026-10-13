"""Library operations for creating, opening, and safely updating a vault."""

from __future__ import annotations

import os
import secrets
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
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
from .errors import (
    DestinationExistsError,
    DuplicateEntryError,
    EntryNotFoundError,
)
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
from .store import (
    ensure_parent_directory,
    read_vault_bytes,
    read_vault_snapshot,
    vault_lock,
    write_new_vault,
    write_updated_vault,
)

__all__ = [
    "default_vault_path",
    "empty_vault",
    "initialize_vault",
    "unlock_vault",
    "update_vault",
    "add_entry",
    "list_entries",
    "get_entry",
    "update_entry",
    "delete_entry",
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
    """Create a new, empty v1 vault, refusing to replace an existing path."""
    ensure_parent_directory(path)
    if os.path.lexists(path):
        raise DestinationExistsError(f"refusing to overwrite existing file: {path}")
    blob = _encrypt_payload(
        empty_vault(), password, vault_id=generate_vault_id(), salt=generate_salt()
    )
    write_new_vault(path, blob)
    return parse_header(blob)


def unlock_vault(path: Path, password: bytes) -> dict[str, Any]:
    """Read and validate a vault without modifying it."""
    return _decrypt_vault_bytes(read_vault_bytes(path), password)


def update_vault(
    path: Path,
    password: bytes,
    transform: Callable[[dict[str, Any]], Mapping[str, Any]],
) -> None:
    """Apply and persist a payload transformation under an exclusive vault lock.

    The transform runs only after authentication, while the stable sibling lock
    is held. It must return a complete payload; schema and size checks happen
    before any encrypted bytes are committed.
    """
    with vault_lock(path):
        snapshot = read_vault_snapshot(path)
        header = parse_header(snapshot.data)
        payload = _decrypt_vault_bytes(snapshot.data, password)
        updated = transform(payload)
        plaintext = bytearray(serialize_payload(updated))
        kek = bytearray()
        try:
            kek = bytearray(derive_kek(password, header.salt))
            blob = _encrypt_payload_bytes(
                plaintext,
                kek,
                vault_id=header.vault_id,
                salt=header.salt,
            )
            write_updated_vault(path, blob, snapshot)
        finally:
            wipe(kek)
            wipe(plaintext)


def add_entry(
    path: Path,
    password: bytes,
    *,
    entry_type: str,
    title: str,
    fields: Mapping[str, Any],
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Create an entry with a fresh stable ID and persist it atomically."""
    now = int(datetime.now(timezone.utc).timestamp())
    entry = {
        "id": secrets.token_hex(16),
        "type": entry_type,
        "title": title,
        "tags": list(tags) if tags is not None else [],
        "created_at": now,
        "updated_at": now,
        "fields": dict(fields),
    }

    def add(payload: dict[str, Any]) -> Mapping[str, Any]:
        if any(existing["id"] == entry["id"] for existing in payload["entries"]):
            raise DuplicateEntryError("an entry with this ID already exists")
        payload["entries"].append(entry)
        return payload

    update_vault(path, password, add)
    return entry


def list_entries(path: Path, password: bytes) -> list[dict[str, Any]]:
    """Return all validated entries; callers choose safe fields for display."""
    return unlock_vault(path, password)["entries"]


def get_entry(path: Path, password: bytes, entry_id: str) -> dict[str, Any]:
    """Return an entry selected by its stable ID, not its editable title."""
    for entry in list_entries(path, password):
        if entry["id"] == entry_id:
            return entry
    raise EntryNotFoundError("entry not found")


def update_entry(
    path: Path,
    password: bytes,
    entry_id: str,
    *,
    title: str | None = None,
    fields: Mapping[str, Any] | None = None,
    tags: list[str] | None = None,
) -> None:
    """Update only supplied entry properties, preserving ID and other fields."""
    if title is None and fields is None and tags is None:
        raise ValueError("at least one entry property must be supplied")
    field_updates = dict(fields) if fields is not None else None
    tag_updates = list(tags) if tags is not None else None
    modified_at = int(datetime.now(timezone.utc).timestamp())

    def update(payload: dict[str, Any]) -> Mapping[str, Any]:
        entry = next((item for item in payload["entries"] if item["id"] == entry_id), None)
        if entry is None:
            raise EntryNotFoundError("entry not found")
        if title is not None:
            entry["title"] = title
        if field_updates is not None:
            entry["fields"].update(field_updates)
        if tag_updates is not None:
            entry["tags"] = tag_updates
        entry["updated_at"] = modified_at
        return payload

    update_vault(path, password, update)


def delete_entry(path: Path, password: bytes, entry_id: str) -> None:
    """Delete an entry by stable ID and persist the remaining vault."""

    def delete(payload: dict[str, Any]) -> Mapping[str, Any]:
        for index, entry in enumerate(payload["entries"]):
            if entry["id"] == entry_id:
                del payload["entries"][index]
                return payload
        raise EntryNotFoundError("entry not found")

    update_vault(path, password, delete)


def _decrypt_vault_bytes(data: bytes, password: bytes) -> dict[str, Any]:
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


def _encrypt_payload(
    payload: Mapping[str, Any], password: bytes, *, vault_id: bytes, salt: bytes
) -> bytes:
    plaintext = bytearray(serialize_payload(payload))
    kek = bytearray()
    try:
        kek = bytearray(derive_kek(password, salt))
        return _encrypt_payload_bytes(plaintext, kek, vault_id=vault_id, salt=salt)
    finally:
        wipe(kek)
        wipe(plaintext)


def _encrypt_payload_bytes(
    plaintext: bytearray, kek: bytearray, *, vault_id: bytes, salt: bytes
) -> bytes:
    dek = bytearray(generate_dek())
    try:
        wrap_nonce = generate_nonce()
        body_nonce = generate_nonce()
        prefix = build_header_prefix(
            vault_id=vault_id,
            salt=salt,
            wrap_nonce=wrap_nonce,
            body_nonce=body_nonce,
        )
        wrapped_key = wrap_dek(kek, wrap_nonce, dek, aad=wrap_aad(prefix))
        header = assemble_header(prefix, wrapped_key)
        return header + encrypt_body(dek, body_nonce, plaintext, aad=body_aad(header))
    finally:
        wipe(dek)
