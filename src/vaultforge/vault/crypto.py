"""Cryptographic primitives for the encrypted vault (format v1).

This module is intentionally narrow: it exposes the two primitives the format
uses, with strict validation at the boundary, and nothing about the file format
itself (that is :mod:`vaultforge.vault.format`) or the payload schema (that is
:mod:`vaultforge.vault.payload`).

* **Key derivation:** Argon2id (RFC 9106) producing the key-encryption key (KEK)
  from the master password and the per-vault salt.
* **Authenticated encryption:** ChaCha20-Poly1305 (RFC 8439) for both wrapping
  the per-write data key (DEK) and encrypting the body.

Both primitives come from the `cryptography` library; nothing here rolls its own
crypto or uses the ``random`` module. Random values are drawn from
:mod:`secrets` (the OS CSPRNG).

Failures never leak material: parameter errors carry a field name and length at
most, and an authentication failure is always the single, deliberate
:data:`~vaultforge.vault.errors.AUTH_ERROR_MESSAGE`.
"""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from ..limits import (
    MAX_VAULT_ITERATIONS,
    MAX_VAULT_LANES,
    MAX_VAULT_MEMORY_KIB,
    MIN_VAULT_ITERATIONS,
    MIN_VAULT_LANES,
    MIN_VAULT_MEMORY_KIB,
    VAULT_ARGON2_ITERATIONS,
    VAULT_ARGON2_LANES,
    VAULT_ARGON2_MEMORY_KIB,
)
from .errors import AUTH_ERROR_MESSAGE, AuthError, CryptoParameterError

__all__ = [
    "DEK_LEN",
    "KEK_LEN",
    "NONCE_LEN",
    "SALT_LEN",
    "TAG_LEN",
    "argon2id_derive",
    "chacha20poly1305_decrypt",
    "chacha20poly1305_encrypt",
    "decrypt_body",
    "derive_kek",
    "encrypt_body",
    "generate_dek",
    "generate_nonce",
    "generate_salt",
    "unwrap_dek",
    "validate_argon2_params",
    "wipe",
    "wrap_dek",
]

BytesLike = bytes | bytearray | memoryview

KEK_LEN = 32
DEK_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
SALT_LEN = 16
# Argon2id rejects shorter salts; v1 always writes SALT_LEN (16) bytes anyway.
ARGON2_MIN_SALT_LEN = 8


def _check_bytes(name: str, value: object, length: int | None = None) -> None:
    """Require ``value`` to be bytes-like, optionally of an exact length."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise CryptoParameterError(f"{name} must be bytes")
    if length is not None and len(value) != length:
        raise CryptoParameterError(f"{name} must be exactly {length} bytes")


def _check_int(name: str, value: object) -> int:
    """Require a true integer (``bool`` is rejected) and return it."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise CryptoParameterError(f"{name} must be an integer")
    return value


def validate_argon2_params(*, memory_kib: int, iterations: int, lanes: int) -> None:
    """Validate Argon2id parameters against the accepted bounds.

    This runs *before* any derivation so that out-of-range values (which could
    force a huge allocation or a long CPU burn) are refused cheaply. The bounds
    are the format-wide sanity limits; the pinned v1 profile is enforced
    separately by the file parser.
    """
    memory_kib = _check_int("memory_kib", memory_kib)
    iterations = _check_int("iterations", iterations)
    lanes = _check_int("lanes", lanes)

    if not MIN_VAULT_LANES <= lanes <= MAX_VAULT_LANES:
        raise CryptoParameterError(f"lanes must be between {MIN_VAULT_LANES} and {MAX_VAULT_LANES}")
    if not MIN_VAULT_MEMORY_KIB <= memory_kib <= MAX_VAULT_MEMORY_KIB:
        raise CryptoParameterError(
            f"memory_kib must be between {MIN_VAULT_MEMORY_KIB} and {MAX_VAULT_MEMORY_KIB}"
        )
    if memory_kib < 8 * lanes:
        raise CryptoParameterError("memory_kib must be at least 8 * lanes")
    if not MIN_VAULT_ITERATIONS <= iterations <= MAX_VAULT_ITERATIONS:
        raise CryptoParameterError(
            f"iterations must be between {MIN_VAULT_ITERATIONS} and {MAX_VAULT_ITERATIONS}"
        )


def argon2id_derive(
    password: BytesLike,
    *,
    salt: BytesLike,
    length: int = KEK_LEN,
    iterations: int = VAULT_ARGON2_ITERATIONS,
    lanes: int = VAULT_ARGON2_LANES,
    memory_cost: int = VAULT_ARGON2_MEMORY_KIB,
    ad: BytesLike | None = None,
    secret: BytesLike | None = None,
) -> bytes:
    """Derive ``length`` bytes with Argon2id (RFC 9106).

    ``ad`` (associated data) and ``secret`` (a pepper) are exposed so the
    implementation can be checked against the RFC 9106 test vectors; the vault
    format itself passes neither.
    """
    _check_bytes("password", password)
    _check_bytes("salt", salt)
    if len(salt) < ARGON2_MIN_SALT_LEN:
        raise CryptoParameterError(f"salt must be at least {ARGON2_MIN_SALT_LEN} bytes")
    length = _check_int("length", length)
    if length < 1:
        raise CryptoParameterError("length must be a positive integer")
    if ad is not None:
        _check_bytes("ad", ad)
    if secret is not None:
        _check_bytes("secret", secret)
    validate_argon2_params(memory_kib=memory_cost, iterations=iterations, lanes=lanes)

    return Argon2id(
        salt=bytes(salt),
        length=length,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
        ad=bytes(ad) if ad is not None else None,
        secret=bytes(secret) if secret is not None else None,
    ).derive(bytes(password))


def derive_kek(password: BytesLike, salt: BytesLike) -> bytes:
    """Derive the 32-byte KEK for the pinned v1 Argon2id profile.

    Same password + salt + profile always yields the same key, which is what
    lets a vault be reopened. The v1 profile (m=65536, t=3, p=1) is fixed here
    and is not a parameter of the format.
    """
    _check_bytes("password", password)
    _check_bytes("salt", salt, SALT_LEN)
    return argon2id_derive(password, salt=salt, length=KEK_LEN)


def chacha20poly1305_encrypt(
    key: BytesLike,
    nonce: BytesLike,
    plaintext: BytesLike,
    aad: BytesLike,
) -> bytes:
    """Encrypt ``plaintext`` with ChaCha20-Poly1305, returning ciphertext || tag."""
    _check_bytes("key", key, KEK_LEN)
    _check_bytes("nonce", nonce, NONCE_LEN)
    _check_bytes("plaintext", plaintext)
    _check_bytes("aad", aad)
    return ChaCha20Poly1305(bytes(key)).encrypt(bytes(nonce), bytes(plaintext), bytes(aad))


def chacha20poly1305_decrypt(
    key: BytesLike,
    nonce: BytesLike,
    ciphertext: BytesLike,
    aad: BytesLike,
) -> bytes:
    """Decrypt and authenticate; any failure is the unified :class:`AuthError`."""
    _check_bytes("key", key, KEK_LEN)
    _check_bytes("nonce", nonce, NONCE_LEN)
    _check_bytes("ciphertext", ciphertext)
    _check_bytes("aad", aad)
    if len(ciphertext) < TAG_LEN:
        # Too short to even contain a tag: a structural problem, not an auth one.
        raise CryptoParameterError("ciphertext must be at least 16 bytes (tag)")
    try:
        return ChaCha20Poly1305(bytes(key)).decrypt(bytes(nonce), bytes(ciphertext), bytes(aad))
    except InvalidTag as exc:
        raise AuthError(AUTH_ERROR_MESSAGE) from exc


def wrap_dek(
    kek: BytesLike,
    wrap_nonce: BytesLike,
    dek: BytesLike,
    *,
    aad: BytesLike,
) -> bytes:
    """Wrap a 32-byte DEK under the KEK, yielding a 48-byte wrapped key."""
    _check_bytes("dek", dek, DEK_LEN)
    return chacha20poly1305_encrypt(kek, wrap_nonce, dek, aad)


def unwrap_dek(
    kek: BytesLike,
    wrap_nonce: BytesLike,
    wrapped_key: BytesLike,
    *,
    aad: BytesLike,
) -> bytes:
    """Recover the 32-byte DEK, or raise :class:`AuthError`."""
    _check_bytes("wrapped_key", wrapped_key, DEK_LEN + TAG_LEN)
    dek = chacha20poly1305_decrypt(kek, wrap_nonce, wrapped_key, aad)
    if len(dek) != DEK_LEN:
        raise AuthError(AUTH_ERROR_MESSAGE)
    return dek


def encrypt_body(
    dek: BytesLike,
    body_nonce: BytesLike,
    payload: BytesLike,
    *,
    aad: BytesLike,
) -> bytes:
    """Encrypt the canonical payload under the DEK."""
    _check_bytes("dek", dek, DEK_LEN)
    return chacha20poly1305_encrypt(dek, body_nonce, payload, aad)


def decrypt_body(
    dek: BytesLike,
    body_nonce: BytesLike,
    ciphertext: BytesLike,
    *,
    aad: BytesLike,
) -> bytes:
    """Decrypt the body under the DEK, or raise :class:`AuthError`."""
    _check_bytes("dek", dek, DEK_LEN)
    return chacha20poly1305_decrypt(dek, body_nonce, ciphertext, aad)


def generate_salt() -> bytes:
    """Return a fresh 16-byte per-vault salt from the OS CSPRNG."""
    return secrets.token_bytes(SALT_LEN)


def generate_dek() -> bytes:
    """Return a fresh 32-byte data-encryption key from the OS CSPRNG."""
    return secrets.token_bytes(DEK_LEN)


def generate_nonce() -> bytes:
    """Return a fresh 12-byte ChaCha20-Poly1305 nonce from the OS CSPRNG."""
    return secrets.token_bytes(NONCE_LEN)


def wipe(buffer: bytearray) -> None:
    """Best-effort zeroization of a mutable byte buffer.

    Python gives no guarantee that a value is not copied elsewhere (by the
    interpreter, the allocator, or swap), so this reduces but cannot eliminate
    the window in which key material survives in memory. It only helps when the
    caller keeps the secret in one ``bytearray`` and overwrites it in place.
    """
    for index in range(len(buffer)):
        buffer[index] = 0
