"""Cryptographically secure secret generators.

Design rules enforced here:

* All randomness comes from :mod:`secrets`. The :mod:`random` module is never
  imported or used, because its output is predictable and unsuitable for
  secrets.
* Inputs are validated before any randomness is drawn, so impossible requests
  fail deterministically rather than producing a surprising result.
* Character requirements are satisfied by construction and then *shuffled*
  with a cryptographically secure Fisher-Yates pass, which avoids the common
  bug where required digits/symbols always land in fixed positions.
"""

from __future__ import annotations

import secrets
import string
from collections.abc import MutableSequence

from .limits import MAX_PASSPHRASE_WORDS, MAX_PIN_LENGTH, MAX_TOKEN_BYTES
from .policy import AMBIGUOUS_CHARACTERS, PasswordPolicy, PolicyError
from .wordlist import load_wordlist

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = string.punctuation


def _secure_shuffle(items: MutableSequence[str]) -> None:
    """Shuffle in place using the Fisher-Yates algorithm and ``secrets``.

    ``random.shuffle`` must not be used for secrets: its Mersenne Twister state
    is recoverable from enough output. ``secrets.randbelow`` is drawn from the
    operating system CSPRNG.
    """
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def _check_upper_bound(name: str, value: int, maximum: int) -> None:
    """Reject a parameter above its documented maximum."""
    if value > maximum:
        raise ValueError(f"{name} {value} exceeds the maximum of {maximum}")


def _validate_separator(separator: str) -> None:
    """Reject control characters that would corrupt line-oriented output."""
    if any(ord(char) < 32 or ord(char) == 127 for char in separator):
        raise ValueError("separator must not contain control characters")


def _enabled_pools(policy: PasswordPolicy) -> list[str]:
    """Return the non-empty character pool for each enabled class.

    Raises :class:`~vaultforge.policy.PolicyError` if excluding ambiguous
    characters would leave a requested class with no usable characters.
    """
    pools: list[str] = []
    for name, chars in (
        ("lowercase", LOWERCASE),
        ("uppercase", UPPERCASE),
        ("digits", DIGITS),
        ("symbols", SYMBOLS),
    ):
        if getattr(policy, name):
            pool = (
                "".join(c for c in chars if c not in AMBIGUOUS_CHARACTERS)
                if policy.exclude_ambiguous
                else chars
            )
            if not pool:
                raise PolicyError(f"class '{name}' has no characters left after exclusions")
            pools.append(pool)
    return pools


def generate_password(policy: PasswordPolicy) -> str:
    """Generate a password that satisfies ``policy``.

    Every enabled class is guaranteed to appear at least once, the total length
    is exact, and the result is shuffled so class membership is not positional.
    """
    policy.validate()
    pools = _enabled_pools(policy)

    # One guaranteed character per enabled class...
    chars = [secrets.choice(pool) for pool in pools]
    # ...then fill the remainder from the combined alphabet.
    combined = "".join(pools)
    chars.extend(secrets.choice(combined) for _ in range(policy.length - len(chars)))
    _secure_shuffle(chars)
    return "".join(chars)


def generate_pin(length: int) -> str:
    """Generate a numeric PIN of exactly ``length`` digits.

    A zero-padded *string* is returned (not an integer) so that leading zeroes
    are preserved, which matters for PINs and fixed-width codes.
    """
    if length < 1:
        raise ValueError("length must be >= 1")
    _check_upper_bound("length", length, MAX_PIN_LENGTH)
    return "".join(secrets.choice(DIGITS) for _ in range(length))


def generate_hex_token(nbytes: int) -> str:
    """Return ``nbytes`` of entropy hex-encoded (``2 * nbytes`` characters)."""
    if nbytes < 1:
        raise ValueError("nbytes must be >= 1")
    _check_upper_bound("nbytes", nbytes, MAX_TOKEN_BYTES)
    return secrets.token_hex(nbytes)


def generate_urlsafe_token(nbytes: int) -> str:
    """Return ``nbytes`` of entropy as a URL-safe base64 string.

    The encoded length is variable (base64 pads in 4-character groups and
    ``token_urlsafe`` strips trailing '='), but the embedded entropy is exactly
    ``nbytes`` bytes.
    """
    if nbytes < 1:
        raise ValueError("nbytes must be >= 1")
    _check_upper_bound("nbytes", nbytes, MAX_TOKEN_BYTES)
    return secrets.token_urlsafe(nbytes)


def generate_passphrase(
    word_count: int,
    *,
    separator: str = "-",
    capitalize: bool = False,
) -> str:
    """Generate a passphrase of ``word_count`` words from the bundled list.

    The word list is loaded once and each word is chosen independently with
    :func:`secrets.choice`.
    """
    if word_count < 1:
        raise ValueError("word_count must be >= 1")
    _check_upper_bound("word_count", word_count, MAX_PASSPHRASE_WORDS)
    _validate_separator(separator)
    words = load_wordlist()
    chosen = [secrets.choice(words) for _ in range(word_count)]
    if capitalize:
        chosen = [word.capitalize() for word in chosen]
    return separator.join(chosen)
