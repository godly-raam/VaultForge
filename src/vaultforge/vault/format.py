"""The v1 vault container format: fixed header layout, AAD, and parsing.

This module knows the *bytes* of a vault file -- where each field lives, which
slices are authenticated, and how to reject a malformed header cheaply. It does
not derive keys or decrypt (that is :mod:`vaultforge.vault.crypto`) and it does
not interpret the payload (that is :mod:`vaultforge.vault.payload`).

Layout (all integers unsigned big-endian; see ``docs/VAULT_FORMAT.md``)::

    offset  size  field
       0      5   magic            = b"VLTFG"
       5      1   format_version   = 0x01
       6     16   vault_id         random, per vault
      22      4   argon2_memory_kib (uint32)
      26      4   argon2_iterations (uint32)
      30      4   argon2_lanes      (uint32)
      34     16   argon2_salt       random, per vault
      50     12   wrap_nonce        random, per write
      62     12   body_nonce        random, per write
      74     48   wrapped_key       AEAD(KEK, wrap_nonce, DEK, wrap_aad)
     122    var   body_ciphertext   AEAD(DEK, body_nonce, payload, body_aad)

There are no trusted length fields: the body is exactly the remainder of the
file. Both AEAD operations authenticate slices of the file itself, so a field
cannot be changed without invalidating a tag.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from ..limits import (
    MAX_VAULT_FILE_BYTES,
    VAULT_ARGON2_ITERATIONS,
    VAULT_ARGON2_LANES,
    VAULT_ARGON2_MEMORY_KIB,
)
from .crypto import DEK_LEN, NONCE_LEN, SALT_LEN, TAG_LEN, validate_argon2_params
from .errors import (
    CryptoParameterError,
    InvalidVaultError,
    NotAVaultError,
    UnsupportedVersionError,
)

__all__ = [
    "FORMAT_VERSION",
    "HEADER_LEN",
    "HEADER_PREFIX_LEN",
    "MAGIC",
    "MAX_FILE_LEN",
    "MIN_FILE_LEN",
    "VAULT_ID_LEN",
    "WRAPPED_KEY_LEN",
    "VaultHeader",
    "assemble_header",
    "body_aad",
    "build_header_prefix",
    "check_file_size",
    "generate_vault_id",
    "parse_header",
    "validate_kdf_params",
    "wrap_aad",
]

MAGIC = b"VLTFG"
MAGIC_LEN = 5
FORMAT_VERSION = 1

VAULT_ID_LEN = 16

OFFSET_MAGIC = 0
OFFSET_VERSION = OFFSET_MAGIC + MAGIC_LEN
OFFSET_VAULT_ID = OFFSET_VERSION + 1
OFFSET_MEMORY = OFFSET_VAULT_ID + VAULT_ID_LEN
OFFSET_ITERATIONS = OFFSET_MEMORY + 4
OFFSET_LANES = OFFSET_ITERATIONS + 4
OFFSET_SALT = OFFSET_LANES + 4
OFFSET_WRAP_NONCE = OFFSET_SALT + SALT_LEN
OFFSET_BODY_NONCE = OFFSET_WRAP_NONCE + NONCE_LEN
OFFSET_WRAPPED_KEY = OFFSET_BODY_NONCE + NONCE_LEN

HEADER_PREFIX_LEN = OFFSET_WRAPPED_KEY  # 74: everything before the wrapped key
WRAPPED_KEY_LEN = DEK_LEN + TAG_LEN  # 48
HEADER_LEN = HEADER_PREFIX_LEN + WRAPPED_KEY_LEN  # 122
MIN_FILE_LEN = HEADER_LEN + TAG_LEN  # 138: header + at least a body tag
MAX_FILE_LEN = MAX_VAULT_FILE_BYTES  # 16 MiB

_UINT32_MAX = 0xFFFFFFFF


@dataclass(frozen=True)
class VaultHeader:
    """The parsed, validated header of a v1 vault.

    ``wrapped_key`` is included because the body AAD authenticates it, but note
    it lives *after* :data:`HEADER_PREFIX_LEN`, so it is deliberately absent
    from :func:`wrap_aad`.
    """

    format_version: int
    vault_id: bytes
    memory_kib: int
    iterations: int
    lanes: int
    salt: bytes
    wrap_nonce: bytes
    body_nonce: bytes
    wrapped_key: bytes


def _expect_len(name: str, value: bytes, length: int) -> None:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise CryptoParameterError(f"{name} must be bytes")
    if len(value) != length:
        raise CryptoParameterError(f"{name} must be exactly {length} bytes")


def _uint32(name: str, value: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CryptoParameterError(f"{name} must be an integer")
    if not 0 <= value <= _UINT32_MAX:
        raise CryptoParameterError(f"{name} must fit in an unsigned 32-bit integer")
    return value.to_bytes(4, "big")


def generate_vault_id() -> bytes:
    """Return a fresh 16-byte vault identifier from the OS CSPRNG."""
    return secrets.token_bytes(VAULT_ID_LEN)


def check_file_size(size: int) -> None:
    """Reject a file size outside ``[MIN_FILE_LEN, MAX_FILE_LEN]``.

    Called before the file is read so an attacker cannot force a huge
    allocation by pointing the tool at a giant or truncated file.
    """
    if size < MIN_FILE_LEN:
        raise InvalidVaultError(f"vault file is too short: {size} bytes (minimum {MIN_FILE_LEN})")
    if size > MAX_FILE_LEN:
        raise InvalidVaultError(f"vault file is too large: {size} bytes (maximum {MAX_FILE_LEN})")


def validate_kdf_params(*, memory_kib: int, iterations: int, lanes: int) -> None:
    """Range-check stored KDF parameters and require the pinned v1 profile.

    Raises :class:`InvalidVaultError` (not the lower-level
    :class:`CryptoParameterError`) so a bad header is reported consistently.
    """
    try:
        validate_argon2_params(memory_kib=memory_kib, iterations=iterations, lanes=lanes)
    except CryptoParameterError as exc:
        raise InvalidVaultError(str(exc)) from exc

    if (memory_kib, iterations, lanes) != (
        VAULT_ARGON2_MEMORY_KIB,
        VAULT_ARGON2_ITERATIONS,
        VAULT_ARGON2_LANES,
    ):
        raise InvalidVaultError("unsupported Argon2id profile for format v1")


def build_header_prefix(
    *,
    vault_id: bytes,
    salt: bytes,
    wrap_nonce: bytes,
    body_nonce: bytes,
    memory_kib: int = VAULT_ARGON2_MEMORY_KIB,
    iterations: int = VAULT_ARGON2_ITERATIONS,
    lanes: int = VAULT_ARGON2_LANES,
) -> bytes:
    """Serialize the fixed 74-byte cleartext prefix ``[0, 74)``.

    The KDF profile is *not* checked here, so callers and tests can construct
    tampered headers on purpose; :func:`parse_header` is where the profile is
    enforced.
    """
    _expect_len("vault_id", vault_id, VAULT_ID_LEN)
    _expect_len("salt", salt, SALT_LEN)
    _expect_len("wrap_nonce", wrap_nonce, NONCE_LEN)
    _expect_len("body_nonce", body_nonce, NONCE_LEN)

    prefix = b"".join(
        (
            MAGIC,
            bytes((FORMAT_VERSION,)),
            bytes(vault_id),
            _uint32("memory_kib", memory_kib),
            _uint32("iterations", iterations),
            _uint32("lanes", lanes),
            bytes(salt),
            bytes(wrap_nonce),
            bytes(body_nonce),
        )
    )
    if len(prefix) != HEADER_PREFIX_LEN:  # pragma: no cover - invariant
        raise InvalidVaultError("internal error: header prefix is not 74 bytes")
    return prefix


def assemble_header(prefix: bytes, wrapped_key: bytes) -> bytes:
    """Append a 48-byte wrapped key to a 74-byte prefix, yielding the header."""
    _expect_len("prefix", prefix, HEADER_PREFIX_LEN)
    _expect_len("wrapped_key", wrapped_key, WRAPPED_KEY_LEN)
    return bytes(prefix) + bytes(wrapped_key)


def wrap_aad(file_bytes: bytes) -> bytes:
    """Return ``file_bytes[0:74]`` -- the AAD that authenticates the wrapped DEK."""
    return bytes(file_bytes[:HEADER_PREFIX_LEN])


def body_aad(file_bytes: bytes) -> bytes:
    """Return ``file_bytes[0:122]`` -- the AAD that authenticates the body."""
    return bytes(file_bytes[:HEADER_LEN])


def parse_header(data: bytes) -> VaultHeader:
    """Parse and validate a v1 header from the start of ``data``.

    Runs the cheap structural checks (length, magic, version, KDF bounds and
    profile) in a fixed order and raises a typed error at the first failure,
    before any key derivation takes place.
    """
    if len(data) < HEADER_LEN:
        raise InvalidVaultError(
            f"vault file is too short for a header: {len(data)} bytes (need {HEADER_LEN})"
        )
    if data[OFFSET_MAGIC:OFFSET_VERSION] != MAGIC:
        raise NotAVaultError("not a VaultForge vault: bad magic")

    version = data[OFFSET_VERSION]
    if version != FORMAT_VERSION:
        raise UnsupportedVersionError(f"unsupported vault format version {version}")

    vault_id = bytes(data[OFFSET_VAULT_ID:OFFSET_MEMORY])
    memory_kib = int.from_bytes(data[OFFSET_MEMORY:OFFSET_ITERATIONS], "big")
    iterations = int.from_bytes(data[OFFSET_ITERATIONS:OFFSET_LANES], "big")
    lanes = int.from_bytes(data[OFFSET_LANES:OFFSET_SALT], "big")
    salt = bytes(data[OFFSET_SALT:OFFSET_WRAP_NONCE])
    wrap_nonce = bytes(data[OFFSET_WRAP_NONCE:OFFSET_BODY_NONCE])
    body_nonce = bytes(data[OFFSET_BODY_NONCE:OFFSET_WRAPPED_KEY])
    wrapped_key = bytes(data[OFFSET_WRAPPED_KEY:HEADER_LEN])

    validate_kdf_params(memory_kib=memory_kib, iterations=iterations, lanes=lanes)

    return VaultHeader(
        format_version=version,
        vault_id=vault_id,
        memory_kib=memory_kib,
        iterations=iterations,
        lanes=lanes,
        salt=salt,
        wrap_nonce=wrap_nonce,
        body_nonce=body_nonce,
        wrapped_key=wrapped_key,
    )
