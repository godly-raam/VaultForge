"""Exception hierarchy for the encrypted vault.

Every error carries a human-readable message that never includes secret
material (the master password, the KEK/DEK, or decrypted payload bytes). The
distinctions matter: the CLI (and any caller) must be able to tell "this is not
a vault" from "this vault needs a newer build" from "authentication failed"
without ever guessing which of the latter was caused by a wrong password versus
tampering -- the Poly1305 tags simply cannot tell them apart, so neither may we.
"""

from __future__ import annotations

__all__ = [
    "AUTH_ERROR_MESSAGE",
    "ActiveVaultDestinationError",
    "AuthError",
    "ConcurrentModificationError",
    "CorruptPayloadError",
    "CryptoParameterError",
    "DestinationExistsError",
    "DuplicateEntryError",
    "EntryNotFoundError",
    "InvalidVaultError",
    "NotAVaultError",
    "PayloadValidationError",
    "UnsupportedFilesystemError",
    "UnsupportedVersionError",
    "VaultError",
]

# The single message used for every authentication failure. Deliberately says
# "or" rather than claiming to know whether the password was wrong or the file
# was tampered with.
AUTH_ERROR_MESSAGE = (
    "authentication failed: wrong master password, or the vault is corrupted "
    "or has been tampered with"
)


class VaultError(Exception):
    """Base class for all vault errors."""


class CryptoParameterError(VaultError):
    """A cryptographic primitive was handed an invalid or out-of-range parameter.

    This signals a programming error or malformed request at the API boundary,
    not a corrupt vault file. Messages never echo the offending bytes.
    """


class NotAVaultError(VaultError):
    """The file does not begin with the vault magic."""


class UnsupportedVersionError(VaultError):
    """The file declares a format version this build does not support."""


class InvalidVaultError(VaultError):
    """The file is structurally invalid.

    Raised for a size outside the allowed range, out-of-bounds or non-v1 KDF
    parameters, or any other fixed-layout violation detected before the KDF runs.
    """


class AuthError(VaultError):
    """Authentication failed.

    Always carries :data:`AUTH_ERROR_MESSAGE`. Covers a wrong master password
    and any tampering that invalidates a tag; the two are indistinguishable.
    """


class PayloadValidationError(VaultError):
    """A vault payload violates the schema.

    Raised on the write path for invalid input, and internally on the read path
    before being re-raised as :class:`CorruptPayloadError`.
    """


class CorruptPayloadError(PayloadValidationError):
    """The payload decrypted successfully but is not valid vault JSON/schema."""


class DestinationExistsError(VaultError):
    """A destination path already exists; the operation refuses to overwrite it."""


class ActiveVaultDestinationError(VaultError):
    """Restore output resolves to the active vault or a detectable alias of it."""


class DuplicateEntryError(VaultError):
    """An entry ID is already present in the vault."""


class EntryNotFoundError(VaultError):
    """An entry ID does not exist in the vault."""


class UnsupportedFilesystemError(VaultError):
    """The filesystem cannot provide a required atomic no-clobber primitive.

    Creating a new vault relies on a hard link (``os.link``) to publish the
    finished file without ever overwriting an existing one. Where hard links are
    unavailable, VaultForge refuses to weaken that guarantee and fails instead of
    writing the destination through a path that a crash could leave partial.
    """


class ConcurrentModificationError(VaultError):
    """The vault changed underneath a read-modify-write operation."""
