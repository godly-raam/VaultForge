"""Upper bounds for generation parameters.

These caps are deliberately far beyond any realistic use. They exist so that a
typo such as ``--length 5000000`` fails fast with a clear message instead of
allocating a multi-megabyte string or monopolising the CPU. Large-output
requests cannot be made "safe" by randomness; they are simply refused.

Enforcement lives in the library (not only in the CLI) so that programmatic
callers receive the same protection.
"""

from __future__ import annotations

MAX_PASSWORD_LENGTH = 4096
MAX_PIN_LENGTH = 4096
MAX_TOKEN_BYTES = 4096
MAX_PASSPHRASE_WORDS = 256
MAX_COUNT = 10000

# TOTP / HOTP parameters (RFC 6238 / RFC 4226).
DEFAULT_OTP_SECRET_BYTES = 20  # 160 bits, the RFC 4226 recommended HMAC-SHA-1 key size
MIN_OTP_SECRET_BYTES = 20
MAX_OTP_SECRET_BYTES = 128
DEFAULT_OTP_DIGITS = 6
DEFAULT_OTP_PERIOD = 30
MIN_OTP_PERIOD = 1
MAX_OTP_PERIOD = 3600
# Clock-skew window is expressed in whole time steps checked on each side.
MAX_OTP_WINDOW = 10

# Encrypted vault (format v1). See docs/VAULT_FORMAT.md.
#
# The Argon2id bounds below are checked *before* the KDF runs, so a crafted
# header cannot coerce an unbounded, memory-hungry derivation (denial of
# service / out-of-memory). They are deliberately far wider than the single
# profile v1 writes; the profile itself is pinned separately.
MIN_VAULT_MEMORY_KIB = 8
MAX_VAULT_MEMORY_KIB = 1_048_576
MIN_VAULT_ITERATIONS = 1
MAX_VAULT_ITERATIONS = 10
MIN_VAULT_LANES = 1
MAX_VAULT_LANES = 4

# The one Argon2id profile written by v1 (RFC 9106). A v1 reader treats any
# other profile as an unsupported vault, keeping the format unambiguous.
VAULT_ARGON2_MEMORY_KIB = 65_536
VAULT_ARGON2_ITERATIONS = 3
VAULT_ARGON2_LANES = 1

# Container size gate (checked before the whole file is read into memory).
MAX_VAULT_FILE_BYTES = 16 * 1024 * 1024  # 16 MiB

# Payload caps (checked after decryption, before allocation-heavy work).
MAX_VAULT_ENTRIES = 100_000
MAX_VAULT_PAYLOAD_BYTES = 16 * 1024 * 1024  # 16 MiB
MAX_VAULT_FIELD_BYTES = 65_536  # characters in any single string field
MAX_VAULT_TAGS = 64
MAX_VAULT_JSON_DEPTH = 64
