"""Tests that generated secrets do not leak through unexpected channels.

The CLI is *supposed* to print the secret to stdout. Everything else -- stderr,
the logging subsystem, and the library's own std streams -- must stay silent.
"""

import base64
import logging

import pytest
from typer.testing import CliRunner

from vaultforge import generators
from vaultforge import otp as otp_lib
from vaultforge.cli import app
from vaultforge.policy import PasswordPolicy

runner = CliRunner()

OTP_SECRET = base64.b32encode(b"12345678901234567890").decode()


def _stderr(result) -> str:
    return getattr(result, "stderr", "") or ""


def test_library_writes_nothing_to_standard_streams(capsys):
    generators.generate_password(PasswordPolicy(length=16))
    generators.generate_pin(6)
    generators.generate_hex_token(8)
    generators.generate_urlsafe_token(8)
    generators.generate_passphrase(4)
    otp_lib.generate_secret()
    otp_lib.generate_code(OTP_SECRET, for_time=0)
    otp_lib.verify_code(OTP_SECRET, otp_lib.generate_code(OTP_SECRET, for_time=0), for_time=0)
    otp_lib.provisioning_uri(OTP_SECRET, name="a@b.c")

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_library_emits_no_log_records(caplog):
    with caplog.at_level(logging.DEBUG):
        generators.generate_password(PasswordPolicy(length=16))
        generators.generate_pin(6)
        generators.generate_hex_token(8)
        generators.generate_urlsafe_token(8)
        generators.generate_passphrase(4)
        otp_lib.generate_secret()
        otp_lib.generate_code(OTP_SECRET, for_time=0)
        otp_lib.provisioning_uri(OTP_SECRET, name="a@b.c")

    assert caplog.records == []


def test_vaultforge_logger_has_no_handlers():
    assert logging.getLogger("vaultforge").handlers == []


@pytest.mark.parametrize(
    "args",
    [
        ["password", "--length", "16"],
        ["pin", "--digits", "6"],
        ["token", "--bytes", "16"],
        ["token", "--bytes", "16", "--encoding", "urlsafe"],
        ["passphrase", "--words", "4"],
    ],
)
def test_cli_success_prints_one_secret_to_stdout_and_nothing_to_stderr(args):
    result = runner.invoke(app, args)

    assert result.exit_code == 0
    assert _stderr(result) == ""

    lines = result.stdout.strip().splitlines()
    assert len(lines) == 1
    secret = lines[0]
    assert secret
    # The secret must appear exactly once and never on stderr.
    assert result.stdout.count(secret) == 1
    assert secret not in _stderr(result)


def test_otp_generate_does_not_echo_the_secret(tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text(OTP_SECRET + "\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["otp", "generate", "--secret-file", str(secret_file), "--at", "59", "--digits", "8"],
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == "94287082"
    # The secret is the input; only the derived code reaches the terminal.
    assert OTP_SECRET not in result.stdout
    assert OTP_SECRET not in _stderr(result)
