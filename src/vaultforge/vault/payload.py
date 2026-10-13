"""Canonical JSON serialization and strict parsing of the vault payload.

The decrypted body of a vault is UTF-8 JSON. On the write side it is emitted in
a single canonical form so that the same logical vault always produces the same
bytes (deterministic ciphertext inputs, easy testing, no ambiguity). On the read
side it is treated as hostile: only :func:`json.loads` is used (never
``pickle``/``eval``/``exec``), duplicate keys and floating-point or non-finite
numbers are rejected, nesting depth is bounded, and the result is checked
against the schema before any of it is relied upon.

Error messages here never echo values from the payload, so a hostile file cannot
smuggle plaintext into a traceback.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from ..limits import (
    MAX_OTP_PERIOD,
    MAX_VAULT_ENTRIES,
    MAX_VAULT_FIELD_BYTES,
    MAX_VAULT_JSON_DEPTH,
    MAX_VAULT_PAYLOAD_BYTES,
    MAX_VAULT_TAGS,
    MIN_OTP_PERIOD,
)
from .errors import CorruptPayloadError, PayloadValidationError

__all__ = [
    "ENTRY_TYPES",
    "SCHEMA_VERSION",
    "deserialize_payload",
    "serialize_payload",
    "validate_vault",
]

SCHEMA_VERSION = 1
ENTRY_TYPES = frozenset({"login", "totp", "recovery", "note"})
TOTP_ALGORITHMS = frozenset({"sha1", "sha256", "sha512"})
TOTP_DIGITS = frozenset({6, 7, 8})

_TOP_LEVEL_KEYS = frozenset({"schema", "entries"})
_ENTRY_KEYS = frozenset({"id", "type", "title", "tags", "created_at", "updated_at", "fields"})
_ID_RE = re.compile(r"^[0-9a-f]{32}$")

_REQUIRED_FIELDS: dict[str, frozenset[str]] = {
    "login": frozenset({"username", "password"}),
    "totp": frozenset({"secret", "digits", "period", "algorithm"}),
    "recovery": frozenset({"codes"}),
    "note": frozenset({"body"}),
}
_OPTIONAL_FIELDS: dict[str, frozenset[str]] = {
    "login": frozenset({"url", "notes"}),
    "totp": frozenset({"issuer", "account"}),
    "recovery": frozenset({"notes"}),
    "note": frozenset(),
}


class _JSONRejected(ValueError):
    """Internal marker for JSON the stdlib accepts but the vault format forbids."""


def _object_pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _JSONRejected("payload contains duplicate object keys")
        result[key] = value
    return result


def _reject_float(token: str) -> Any:
    raise _JSONRejected("payload must not contain floating-point numbers")


def _reject_constant(token: str) -> Any:
    raise _JSONRejected("payload must not contain non-finite numbers")


def validate_vault(vault: Any) -> None:
    """Validate a vault object against the schema, or raise a typed error."""
    _check_depth(vault)
    if not isinstance(vault, Mapping):
        raise PayloadValidationError("payload must be a JSON object")

    keys = set(vault)
    if keys - _TOP_LEVEL_KEYS:
        raise PayloadValidationError("payload contains unknown top-level keys")
    missing = _TOP_LEVEL_KEYS - keys
    if missing:
        raise PayloadValidationError("payload is missing required top-level keys")
    if vault["schema"] != SCHEMA_VERSION:
        raise PayloadValidationError("payload has an unsupported schema version")

    entries = vault["entries"]
    if not isinstance(entries, list):
        raise PayloadValidationError("payload 'entries' must be a list")
    if len(entries) > MAX_VAULT_ENTRIES:
        raise PayloadValidationError("payload contains too many entries")
    entry_ids: set[str] = set()
    for index, entry in enumerate(entries):
        _validate_entry(index, entry)
        entry_id = entry["id"]
        if entry_id in entry_ids:
            raise PayloadValidationError("payload contains duplicate entry IDs")
        entry_ids.add(entry_id)


def serialize_payload(vault: Mapping[str, Any]) -> bytes:
    """Return the canonical UTF-8 JSON encoding of a validated vault."""
    validate_vault(vault)
    try:
        encoded = json.dumps(
            vault,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:  # pragma: no cover - validate_vault guards types
        raise PayloadValidationError("payload is not JSON-serializable") from exc
    if len(encoded) > MAX_VAULT_PAYLOAD_BYTES:
        raise PayloadValidationError("payload exceeds the maximum size")
    return encoded


def deserialize_payload(data: bytes) -> dict[str, Any]:
    """Parse and validate a decrypted payload, or raise :class:`CorruptPayloadError`."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise CorruptPayloadError("payload must be bytes")
    if len(data) > MAX_VAULT_PAYLOAD_BYTES:
        raise CorruptPayloadError("payload exceeds the maximum size")

    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CorruptPayloadError("payload is not valid UTF-8") from exc

    try:
        obj = json.loads(
            text,
            object_pairs_hook=_object_pairs_no_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except _JSONRejected as exc:
        raise CorruptPayloadError(str(exc)) from exc
    except RecursionError as exc:
        raise CorruptPayloadError("payload nesting is too deep") from exc
    except ValueError as exc:
        # Includes json.JSONDecodeError and the integer-string-digit limit.
        raise CorruptPayloadError("payload is not valid JSON") from exc

    try:
        validate_vault(obj)
    except PayloadValidationError as exc:
        raise CorruptPayloadError(str(exc)) from exc
    if not isinstance(obj, dict):  # pragma: no cover - validate_vault enforces this
        raise CorruptPayloadError("payload must be a JSON object")
    return obj


def _check_depth(value: Any) -> None:
    """Reject nesting deeper than the cap, and non-string object keys.

    Iterative rather than recursive so the check itself cannot exhaust the
    interpreter stack on a deeply nested payload.
    """
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        obj, depth = stack.pop()
        if depth > MAX_VAULT_JSON_DEPTH:
            raise PayloadValidationError("payload nesting is too deep")
        if isinstance(obj, dict):
            for key, item in obj.items():
                if not isinstance(key, str):
                    raise PayloadValidationError("payload object keys must be strings")
                stack.append((item, depth + 1))
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                stack.append((item, depth + 1))


def _require_string(where: str, value: Any, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise PayloadValidationError(f"{where} must be a string")
    if len(value) > MAX_VAULT_FIELD_BYTES:
        raise PayloadValidationError(f"{where} is too long")
    if not allow_empty and not value:
        raise PayloadValidationError(f"{where} must not be empty")
    return value


def _require_int(where: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PayloadValidationError(f"{where} must be an integer")
    return value


def _validate_entry(index: int, entry: Any) -> None:
    where = f"entry {index}"
    if not isinstance(entry, Mapping):
        raise PayloadValidationError(f"{where} must be a JSON object")

    keys = set(entry)
    if keys - _ENTRY_KEYS:
        raise PayloadValidationError(f"{where} contains unknown keys")
    if _ENTRY_KEYS - keys:
        raise PayloadValidationError(f"{where} is missing required keys")

    entry_id = entry["id"]
    if not isinstance(entry_id, str) or not _ID_RE.match(entry_id):
        raise PayloadValidationError(f"{where} id must be 32 lowercase hex characters")

    entry_type = entry["type"]
    if not isinstance(entry_type, str) or entry_type not in ENTRY_TYPES:
        raise PayloadValidationError(f"{where} has an unknown type")

    _require_string(f"{where} title", entry["title"])

    tags = entry["tags"]
    if not isinstance(tags, list):
        raise PayloadValidationError(f"{where} tags must be a list")
    if len(tags) > MAX_VAULT_TAGS:
        raise PayloadValidationError(f"{where} has too many tags")
    for tag in tags:
        _require_string(f"{where} tag", tag)

    _require_int(f"{where} created_at", entry["created_at"])
    _require_int(f"{where} updated_at", entry["updated_at"])

    _validate_fields(index, entry_type, entry["fields"])


def _validate_fields(index: int, entry_type: str, fields: Any) -> None:
    where = f"entry {index} ({entry_type}) fields"
    if not isinstance(fields, Mapping):
        raise PayloadValidationError(f"{where} must be a JSON object")

    keys = set(fields)
    allowed = _REQUIRED_FIELDS[entry_type] | _OPTIONAL_FIELDS[entry_type]
    if keys - allowed:
        raise PayloadValidationError(f"{where} contains unknown keys")
    if _REQUIRED_FIELDS[entry_type] - keys:
        raise PayloadValidationError(f"{where} is missing required keys")

    if entry_type == "login":
        _require_string(f"{where} username", fields["username"])
        _require_string(f"{where} password", fields["password"])
        for optional in ("url", "notes"):
            if optional in fields:
                _require_string(f"{where} {optional}", fields[optional])
    elif entry_type == "totp":
        _require_string(f"{where} secret", fields["secret"], allow_empty=False)
        digits = _require_int(f"{where} digits", fields["digits"])
        if digits not in TOTP_DIGITS:
            raise PayloadValidationError(f"{where} digits must be 6, 7, or 8")
        period = _require_int(f"{where} period", fields["period"])
        if not MIN_OTP_PERIOD <= period <= MAX_OTP_PERIOD:
            raise PayloadValidationError(f"{where} period is out of range")
        algorithm = fields["algorithm"]
        if not isinstance(algorithm, str) or algorithm not in TOTP_ALGORITHMS:
            raise PayloadValidationError(f"{where} algorithm is invalid")
        for optional in ("issuer", "account"):
            if optional in fields:
                _require_string(f"{where} {optional}", fields[optional])
    elif entry_type == "recovery":
        codes = fields["codes"]
        if not isinstance(codes, list):
            raise PayloadValidationError(f"{where} codes must be a list")
        for code in codes:
            _require_string(f"{where} code", code)
        if "notes" in fields:
            _require_string(f"{where} notes", fields["notes"])
    elif entry_type == "note":
        _require_string(f"{where} body", fields["body"])
