"""Boundary tests for the documented parameter caps.

These verify both that the maximum is accepted and that anything above it is
rejected *in the library*, not merely in the CLI. That matters because the
caps exist to protect programmatic callers too.
"""

import pytest

from vaultforge import generators
from vaultforge.limits import (
    MAX_PASSPHRASE_WORDS,
    MAX_PASSWORD_LENGTH,
    MAX_PIN_LENGTH,
    MAX_TOKEN_BYTES,
)
from vaultforge.policy import PasswordPolicy, PolicyError


def test_password_length_at_maximum_is_accepted():
    result = generators.generate_password(PasswordPolicy(length=MAX_PASSWORD_LENGTH))
    assert len(result) == MAX_PASSWORD_LENGTH


def test_password_length_above_maximum_is_rejected():
    with pytest.raises(PolicyError, match="exceeds the maximum"):
        PasswordPolicy(length=MAX_PASSWORD_LENGTH + 1).validate()


def test_pin_length_at_maximum_is_accepted():
    assert len(generators.generate_pin(MAX_PIN_LENGTH)) == MAX_PIN_LENGTH


def test_pin_length_above_maximum_is_rejected():
    with pytest.raises(ValueError, match="exceeds the maximum"):
        generators.generate_pin(MAX_PIN_LENGTH + 1)


def test_hex_token_at_maximum_is_accepted():
    assert len(generators.generate_hex_token(MAX_TOKEN_BYTES)) == 2 * MAX_TOKEN_BYTES


def test_urlsafe_token_at_maximum_is_accepted():
    assert generators.generate_urlsafe_token(MAX_TOKEN_BYTES)


@pytest.mark.parametrize("func", [generators.generate_hex_token, generators.generate_urlsafe_token])
def test_token_bytes_above_maximum_is_rejected(func):
    with pytest.raises(ValueError, match="exceeds the maximum"):
        func(MAX_TOKEN_BYTES + 1)


def test_passphrase_word_count_at_maximum_is_accepted():
    phrase = generators.generate_passphrase(MAX_PASSPHRASE_WORDS)
    assert len(phrase.split("-")) == MAX_PASSPHRASE_WORDS


def test_passphrase_word_count_above_maximum_is_rejected():
    with pytest.raises(ValueError, match="exceeds the maximum"):
        generators.generate_passphrase(MAX_PASSPHRASE_WORDS + 1)


@pytest.mark.parametrize("separator", ["\n", "\r", "\x00", "\t", "a\nb", "del\x7f"])
def test_separator_rejects_control_characters(separator):
    with pytest.raises(ValueError, match="control characters"):
        generators.generate_passphrase(3, separator=separator)


@pytest.mark.parametrize("separator", ["", "-", " ", "::", "_"])
def test_separator_accepts_printable_strings(separator):
    phrase = generators.generate_passphrase(3, separator=separator)
    assert phrase
