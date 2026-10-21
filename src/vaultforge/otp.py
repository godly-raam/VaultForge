"""Time-based one-time passwords (TOTP), built on the PyOTP library.

TOTP is defined by RFC 6238 (which extends the HMAC-based HOTP of RFC 4226).
A shared secret and the current time step are hashed to produce a short numeric
code that changes every ``period`` seconds.

Design rules enforced here:

* PyOTP is an **optional** dependency. It is imported lazily so the password,
  PIN, token, and passphrase commands keep working when it is not installed;
  only the ``otp`` commands raise :class:`OTPError` with an install hint.
* The secret is generated with :func:`secrets.token_bytes` and base32-encoded;
  nothing is logged or written to disk. VaultForge does not enrol, store, or
  transmit secrets -- that is the user's responsibility.
* All time values are normalised to an aware UTC :class:`~datetime.datetime`
  before being handed to PyOTP. Passed as a naive local datetime, the same
  integer timestamp could map to a different counter on a machine in another
  timezone or during a DST transition.
* Parameters are validated before any code is produced, so invalid input fails
  with a clear message instead of a confusing library error.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import secrets
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .limits import (
    DEFAULT_OTP_DIGITS,
    DEFAULT_OTP_PERIOD,
    DEFAULT_OTP_SECRET_BYTES,
    MAX_OTP_PERIOD,
    MAX_OTP_SECRET_BYTES,
    MAX_OTP_WINDOW,
    MIN_OTP_PERIOD,
    MIN_OTP_SECRET_BYTES,
)

# Digits accepted by the `otpauth://` URI format and common authenticator apps.
SUPPORTED_DIGITS = frozenset({6, 7, 8})


class OTPError(ValueError):
    """Raised for invalid TOTP parameters or a missing optional dependency."""


class Algorithm(str, Enum):
    """Hash algorithms permitted by RFC 6238."""

    sha1 = "sha1"
    sha256 = "sha256"
    sha512 = "sha512"


_ALGORITHM_DIGESTS: dict[Algorithm, Any] = {
    Algorithm.sha1: hashlib.sha1,
    Algorithm.sha256: hashlib.sha256,
    Algorithm.sha512: hashlib.sha512,
}


def _load_pyotp() -> Any:
    """Import PyOTP on demand, raising an actionable error if it is absent."""
    try:
        import pyotp
    except ImportError as exc:
        raise OTPError(
            "the 'otp' commands require the optional PyOTP dependency; "
            "install it with: pip install 'vaultforge[otp]'"
        ) from exc
    return pyotp


def _validate_digits(digits: int) -> None:
    if digits not in SUPPORTED_DIGITS:
        raise OTPError(f"digits must be one of {sorted(SUPPORTED_DIGITS)}, got {digits}")


def _validate_period(period: int) -> None:
    if not MIN_OTP_PERIOD <= period <= MAX_OTP_PERIOD:
        raise OTPError(
            f"period must be between {MIN_OTP_PERIOD} and {MAX_OTP_PERIOD} seconds, got {period}"
        )


def _validate_window(window: int) -> None:
    if not 0 <= window <= MAX_OTP_WINDOW:
        raise OTPError(f"valid_window must be between 0 and {MAX_OTP_WINDOW}, got {window}")


def normalize_secret(secret: str) -> str:
    """Return ``secret`` in the canonical form PyOTP expects.

    Authenticator apps commonly display secrets grouped with spaces or dashes
    and may include trailing base32 padding. PyOTP accepts only the bare,
    uppercased string, so those cosmetic characters are removed here and the
    result is checked to be valid base32.
    """
    if not isinstance(secret, str):
        raise OTPError("secret must be a string")

    cleaned = secret.replace(" ", "").replace("-", "").rstrip("=").upper()
    if not cleaned:
        raise OTPError("secret must not be empty")

    padded = cleaned + "=" * (-len(cleaned) % 8)
    try:
        base64.b32decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise OTPError("secret must be a valid base32 string") from exc
    return cleaned


def _coerce_time(for_time: int | float | datetime | None) -> datetime:
    """Return ``for_time`` as an aware UTC datetime.

    ``None`` means "now". Integer/float values are treated as POSIX timestamps
    and naive datetimes are assumed to be UTC, keeping behaviour independent of
    the host timezone.
    """
    if for_time is None:
        return datetime.now(timezone.utc)
    if isinstance(for_time, datetime):
        if for_time.tzinfo is None:
            return for_time.replace(tzinfo=timezone.utc)
        return for_time.astimezone(timezone.utc)
    return datetime.fromtimestamp(float(for_time), tz=timezone.utc)


def _build_totp(
    secret: str,
    *,
    digits: int,
    period: int,
    algorithm: Algorithm,
    name: str | None = None,
    issuer: str | None = None,
) -> Any:
    _validate_digits(digits)
    _validate_period(period)
    pyotp = _load_pyotp()
    return pyotp.TOTP(
        normalize_secret(secret),
        digits=digits,
        digest=_ALGORITHM_DIGESTS[algorithm],
        name=name,
        issuer=issuer,
        interval=period,
    )


def generate_secret(num_bytes: int = DEFAULT_OTP_SECRET_BYTES) -> str:
    """Generate a random base32 TOTP secret.

    The default 20 bytes is the 160-bit key size recommended by RFC 4226 and
    matches what authenticator apps assume for HMAC-SHA-1. The returned string
    is unpadded base32 (PyOTP re-adds padding internally).
    """
    if not MIN_OTP_SECRET_BYTES <= num_bytes <= MAX_OTP_SECRET_BYTES:
        raise OTPError(
            f"secret size must be between {MIN_OTP_SECRET_BYTES} and "
            f"{MAX_OTP_SECRET_BYTES} bytes, got {num_bytes}"
        )
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")


def generate_code(
    secret: str,
    *,
    digits: int = DEFAULT_OTP_DIGITS,
    period: int = DEFAULT_OTP_PERIOD,
    algorithm: Algorithm = Algorithm.sha1,
    for_time: int | float | datetime | None = None,
    counter_offset: int = 0,
) -> str:
    """Return the TOTP code for ``secret`` at ``for_time`` (default: now)."""
    totp = _build_totp(secret, digits=digits, period=period, algorithm=algorithm)
    return str(totp.at(_coerce_time(for_time), counter_offset))


def verify_code(
    secret: str,
    code: str,
    *,
    digits: int = DEFAULT_OTP_DIGITS,
    period: int = DEFAULT_OTP_PERIOD,
    algorithm: Algorithm = Algorithm.sha1,
    for_time: int | float | datetime | None = None,
    valid_window: int = 0,
) -> bool:
    """Return whether ``code`` is valid for ``secret``.

    ``valid_window`` accepts that many extra time steps on each side of the
    current one to tolerate small clock skew. PyOTP performs the comparison in
    constant time, so a wrong-but-similar code leaks no timing information.
    """
    _validate_window(valid_window)
    if not isinstance(code, str):
        raise OTPError("code must be a string")
    normalized = code.strip()
    if not normalized:
        return False

    totp = _build_totp(secret, digits=digits, period=period, algorithm=algorithm)
    return bool(totp.verify(normalized, for_time=_coerce_time(for_time), valid_window=valid_window))


def time_remaining(
    period: int = DEFAULT_OTP_PERIOD,
    *,
    for_time: int | float | datetime | None = None,
) -> int:
    """Return whole seconds until the current code rolls over.

    The result is in ``[1, period]``: at an exact boundary the full ``period``
    is reported, matching the intuition that a fresh code has its whole
    lifetime left.
    """
    _validate_period(period)
    if for_time is None:
        epoch = time.time()
    else:
        epoch = _coerce_time(for_time).timestamp()
    rem = period - (epoch % period)
    if epoch % period == 0.0:
        return period
    return max(1, min(period, int(math.ceil(rem))))


def provisioning_uri(
    secret: str,
    *,
    name: str,
    issuer: str | None = None,
    digits: int = DEFAULT_OTP_DIGITS,
    period: int = DEFAULT_OTP_PERIOD,
    algorithm: Algorithm = Algorithm.sha1,
) -> str:
    """Return an ``otpauth://`` URI for enrolling ``secret`` in an app.

    ``name`` is the account label (usually an email address); ``issuer`` is the
    optional service name. Both are URL-encoded by PyOTP.
    """
    if not name:
        raise OTPError("name must not be empty")
    totp = _build_totp(
        secret, digits=digits, period=period, algorithm=algorithm, name=name, issuer=issuer
    )
    return str(totp.provisioning_uri(name=name, issuer_name=issuer))
