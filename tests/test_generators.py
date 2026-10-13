"""Tests for the core secret generators: passwords, PINs, and tokens."""

import base64
import string

import pytest

from vaultforge import generators
from vaultforge.policy import AMBIGUOUS_CHARACTERS, PasswordPolicy, PolicyError

LETTERS = set(string.ascii_letters)
DIGITS = set(string.digits)
SYMBOLS = set(string.punctuation)


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [8, 16, 32, 64])
def test_password_has_exact_length(length):
    result = generators.generate_password(PasswordPolicy(length=length))
    assert len(result) == length
    assert isinstance(result, str)


def test_password_contains_one_of_every_enabled_class():
    for _ in range(200):
        result = generators.generate_password(PasswordPolicy(length=16))
        assert any(c in LETTERS and c.islower() for c in result)
        assert any(c.isupper() for c in result)
        assert any(c in DIGITS for c in result)
        assert any(c in SYMBOLS for c in result)


def test_length_equal_to_class_count_has_exactly_one_per_class():
    # At the minimum valid length with four classes enabled, the only valid
    # passwords contain exactly one character from each class.
    policy = PasswordPolicy(length=4)
    for _ in range(100):
        result = generators.generate_password(policy)
        assert len(result) == 4
        assert sum(c in string.ascii_lowercase for c in result) == 1
        assert sum(c in string.ascii_uppercase for c in result) == 1
        assert sum(c in DIGITS for c in result) == 1
        assert sum(c in SYMBOLS for c in result) == 1


def test_password_respects_disabled_classes():
    policy = PasswordPolicy(length=40, uppercase=False, symbols=False)
    for _ in range(50):
        result = generators.generate_password(policy)
        assert all(c not in SYMBOLS for c in result)
        assert all(not c.isupper() for c in result)
        assert any(c.islower() for c in result)
        assert any(c in DIGITS for c in result)


def test_exclude_ambiguous_removes_confusing_characters():
    policy = PasswordPolicy(length=64, exclude_ambiguous=True)
    for _ in range(200):
        result = generators.generate_password(policy)
        assert not (set(result) & AMBIGUOUS_CHARACTERS)


def test_single_enabled_class_still_works_with_ambiguous_exclusions():
    # Digits are the only class and are still non-empty after exclusions
    # (only 0 and 1 are ambiguous), so this must succeed.
    policy = PasswordPolicy(
        length=8,
        lowercase=False,
        uppercase=False,
        digits=True,
        symbols=False,
        exclude_ambiguous=True,
    )
    result = generators.generate_password(policy)
    assert len(result) == 8
    assert all(c in DIGITS for c in result)
    assert not (set(result) & AMBIGUOUS_CHARACTERS)


def test_impossible_configuration_raises():
    with pytest.raises(PolicyError):
        generators.generate_password(PasswordPolicy(length=3))


def test_required_characters_are_not_positionally_predictable():
    # With one of each class in a length-4 password, a naive generator would
    # always put (say) the symbol first. After a secure shuffle the class in
    # the first position must vary across samples.
    first_position_classes = set()
    for _ in range(300):
        result = generators.generate_password(PasswordPolicy(length=4))
        first = result[0]
        if first in DIGITS:
            first_position_classes.add("digit")
        elif first in SYMBOLS:
            first_position_classes.add("symbol")
        elif first.islower():
            first_position_classes.add("lower")
        else:
            first_position_classes.add("upper")
    assert len(first_position_classes) >= 2


# ---------------------------------------------------------------------------
# PINs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [1, 4, 6, 12])
def test_pin_has_exact_length_and_only_digits(length):
    for _ in range(50):
        result = generators.generate_pin(length)
        assert len(result) == length
        assert all(c in DIGITS for c in result)


def test_pin_preserves_leading_zeroes_deterministically(monkeypatch):
    monkeypatch.setattr(generators.secrets, "choice", lambda seq: "0")
    assert generators.generate_pin(5) == "00000"


def test_pin_can_begin_with_zero():
    samples = [generators.generate_pin(6) for _ in range(300)]
    assert any(pin.startswith("0") for pin in samples)


def test_pin_rejects_non_positive_length():
    with pytest.raises(ValueError):
        generators.generate_pin(0)


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("nbytes", [1, 8, 16, 32])
def test_hex_token_length_and_alphabet(nbytes):
    result = generators.generate_hex_token(nbytes)
    assert len(result) == 2 * nbytes
    assert all(c in "0123456789abcdef" for c in result)


@pytest.mark.parametrize("nbytes", [1, 8, 16, 32])
def test_urlsafe_token_embeds_requested_bytes(nbytes):
    result = generators.generate_urlsafe_token(nbytes)
    padding = "=" * (-len(result) % 4)
    decoded = base64.urlsafe_b64decode(result + padding)
    assert len(decoded) == nbytes


def test_urlsafe_token_is_url_safe():
    result = generators.generate_urlsafe_token(32)
    assert "+" not in result and "/" not in result


@pytest.mark.parametrize("nbytes", [0, -1])
def test_tokens_reject_non_positive_byte_counts(nbytes):
    with pytest.raises(ValueError):
        generators.generate_hex_token(nbytes)
    with pytest.raises(ValueError):
        generators.generate_urlsafe_token(nbytes)
