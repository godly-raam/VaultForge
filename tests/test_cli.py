"""End-to-end tests for the Typer command line interface."""

import base64
import string

import pytest
from typer.testing import CliRunner

from vaultforge.cli import app
from vaultforge.limits import (
    MAX_COUNT,
    MAX_PASSPHRASE_WORDS,
    MAX_PASSWORD_LENGTH,
    MAX_PIN_LENGTH,
    MAX_TOKEN_BYTES,
)

runner = CliRunner()


def _output(result) -> str:
    """Combine stdout/stderr across Click versions."""
    return (result.stdout or "") + (getattr(result, "stderr", "") or "")


def test_password_default_length():
    result = runner.invoke(app, ["password"])
    assert result.exit_code == 0
    assert len(result.stdout.strip()) == 16


def test_password_custom_length():
    result = runner.invoke(app, ["password", "--length", "32"])
    assert result.exit_code == 0
    assert len(result.stdout.strip()) == 32


def test_password_count_emits_multiple_lines():
    result = runner.invoke(app, ["password", "--length", "20", "--count", "3"])
    assert result.exit_code == 0
    assert len(result.stdout.strip().splitlines()) == 3


def test_password_no_symbols():
    result = runner.invoke(app, ["password", "--length", "40", "--no-symbols", "--count", "20"])
    assert result.exit_code == 0
    for line in result.stdout.strip().splitlines():
        assert not (set(line) & set(string.punctuation))


def test_password_impossible_configuration_fails():
    result = runner.invoke(app, ["password", "--length", "1"])
    assert result.exit_code == 2
    assert "too short" in _output(result)


def test_password_all_classes_disabled_fails():
    result = runner.invoke(
        app,
        [
            "password",
            "--no-lowercase",
            "--no-uppercase",
            "--no-digits",
            "--no-symbols",
        ],
    )
    assert result.exit_code == 2
    assert "at least one character class" in _output(result)


def test_pin_length_and_digits():
    result = runner.invoke(app, ["pin", "--digits", "6"])
    assert result.exit_code == 0
    value = result.stdout.strip()
    assert len(value) == 6
    assert value.isdigit()


def test_pin_rejects_zero_digits():
    result = runner.invoke(app, ["pin", "--digits", "0"])
    assert result.exit_code == 2


def test_token_hex_default():
    result = runner.invoke(app, ["token", "--bytes", "32"])
    assert result.exit_code == 0
    value = result.stdout.strip()
    assert len(value) == 64
    assert all(c in "0123456789abcdef" for c in value)


def test_token_urlsafe_encoding():
    result = runner.invoke(app, ["token", "--bytes", "32", "--encoding", "urlsafe"])
    assert result.exit_code == 0
    value = result.stdout.strip()
    padding = "=" * (-len(value) % 4)
    assert len(base64.urlsafe_b64decode(value + padding)) == 32


def test_passphrase_word_count():
    result = runner.invoke(app, ["passphrase", "--words", "6"])
    assert result.exit_code == 0
    assert len(result.stdout.strip().split("-")) == 6


def test_passphrase_custom_separator_and_capitalize():
    result = runner.invoke(app, ["passphrase", "--words", "4", "--separator", "_", "--capitalize"])
    assert result.exit_code == 0
    words = result.stdout.strip().split("_")
    assert len(words) == 4
    assert all(word[0].isupper() for word in words)


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "vaultforge" in result.stdout.lower()


@pytest.mark.parametrize(
    "args",
    [
        ["password", "--length", str(MAX_PASSWORD_LENGTH + 1)],
        ["pin", "--digits", str(MAX_PIN_LENGTH + 1)],
        ["token", "--bytes", str(MAX_TOKEN_BYTES + 1)],
        ["passphrase", "--words", str(MAX_PASSPHRASE_WORDS + 1)],
    ],
)
def test_parameters_above_maximum_fail(args):
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert "Invalid value" in _output(result)


def test_count_above_maximum_fails():
    result = runner.invoke(app, ["password", "--count", str(MAX_COUNT + 1)])
    assert result.exit_code == 2


def test_separator_with_control_character_fails():
    result = runner.invoke(app, ["passphrase", "--words", "3", "--separator", "\n"])
    assert result.exit_code == 2
    assert "control characters" in _output(result)


def test_maximum_values_are_accepted():
    result = runner.invoke(app, ["password", "--length", str(MAX_PASSWORD_LENGTH), "--count", "1"])
    assert result.exit_code == 0
    assert len(result.stdout.strip()) == MAX_PASSWORD_LENGTH
