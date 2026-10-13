"""End-to-end tests for the ``vaultforge otp`` commands."""

import base64

import pytest
from typer.testing import CliRunner

from vaultforge.cli import app

runner = CliRunner()

# RFC 6238 SHA-1 seed, base32-encoded; its code at T=59 is 94287082.
SECRET = base64.b32encode(b"12345678901234567890").decode()


def _stderr(result) -> str:
    return getattr(result, "stderr", "") or ""


@pytest.fixture
def secret_file(tmp_path):
    path = tmp_path / "secret.txt"
    path.write_text(SECRET + "\n", encoding="utf-8")
    return path


def test_otp_secret_prints_base32():
    result = runner.invoke(app, ["otp", "secret"])
    assert result.exit_code == 0
    value = result.stdout.strip()
    assert len(value) == 32
    assert len(base64.b32decode(value + "=" * (-len(value) % 8))) == 20
    assert _stderr(result) == ""


def test_otp_secret_custom_size():
    result = runner.invoke(app, ["otp", "secret", "--bytes", "32"])
    assert result.exit_code == 0
    value = result.stdout.strip()
    assert len(base64.b32decode(value + "=" * (-len(value) % 8))) == 32


def test_otp_secret_rejects_out_of_range():
    result = runner.invoke(app, ["otp", "secret", "--bytes", "1"])
    assert result.exit_code == 2


def test_otp_generate_matches_rfc_vector(secret_file):
    result = runner.invoke(
        app,
        [
            "otp",
            "generate",
            "--secret-file",
            str(secret_file),
            "--digits",
            "8",
            "--at",
            "59",
        ],
    )
    assert result.exit_code == 0
    assert result.stdout.strip() == "94287082"
    assert _stderr(result) == ""


def test_otp_generate_prompts_for_secret():
    result = runner.invoke(
        app, ["otp", "generate", "--at", "59", "--digits", "8"], input=SECRET + "\n"
    )
    assert result.exit_code == 0
    assert result.stdout.strip() == "94287082"


def test_otp_generate_show_remaining_uses_stderr(secret_file):
    result = runner.invoke(
        app,
        ["otp", "generate", "--secret-file", str(secret_file), "--at", "15", "--show-remaining"],
    )
    assert result.exit_code == 0
    assert result.stdout.strip().isdigit()
    assert "remaining" in _stderr(result)
    # The generated code is the only thing on stdout; the secret is nowhere.
    assert SECRET not in result.stdout
    assert SECRET not in _stderr(result)


def test_otp_generate_rejects_bad_digits(secret_file):
    result = runner.invoke(
        app, ["otp", "generate", "--secret-file", str(secret_file), "--digits", "5"]
    )
    assert result.exit_code == 2


def test_otp_generate_missing_secret_file(tmp_path):
    missing = tmp_path / "nope.txt"
    result = runner.invoke(app, ["otp", "generate", "--secret-file", str(missing)])
    assert result.exit_code == 2


def test_otp_verify_valid(secret_file, tmp_path):
    code_file = tmp_path / "code.txt"
    code_file.write_text("94287082\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "otp",
            "verify",
            "--secret-file",
            str(secret_file),
            "--code-file",
            str(code_file),
            "--digits",
            "8",
            "--at",
            "59",
        ],
    )
    assert result.exit_code == 0
    assert result.stdout.strip() == "valid"


def test_otp_verify_invalid_exits_one(secret_file, tmp_path):
    code_file = tmp_path / "code.txt"
    code_file.write_text("00000000\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "otp",
            "verify",
            "--secret-file",
            str(secret_file),
            "--code-file",
            str(code_file),
            "--digits",
            "8",
            "--at",
            "59",
        ],
    )
    assert result.exit_code == 1
    assert result.stdout.strip() == "invalid"


def test_otp_verify_window(secret_file, tmp_path):
    code_file = tmp_path / "code.txt"
    code_file.write_text("94287082\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "otp",
            "verify",
            "--secret-file",
            str(secret_file),
            "--code-file",
            str(code_file),
            "--digits",
            "8",
            "--at",
            "89",
            "--window",
            "1",
        ],
    )
    assert result.exit_code == 0
    assert result.stdout.strip() == "valid"


def test_otp_uri(secret_file):
    result = runner.invoke(
        app,
        [
            "otp",
            "uri",
            "--secret-file",
            str(secret_file),
            "--name",
            "alice@example.com",
            "--issuer",
            "ACME",
        ],
    )
    assert result.exit_code == 0
    uri = result.stdout.strip()
    assert uri.startswith("otpauth://totp/")
    assert f"secret={SECRET}" in uri
    assert "issuer=ACME" in uri


def test_otp_uri_requires_name(secret_file):
    result = runner.invoke(app, ["otp", "uri", "--secret-file", str(secret_file)])
    assert result.exit_code == 2
