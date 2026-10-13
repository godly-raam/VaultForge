"""Behavioural tests for the TOTP library module.

Known-answer vectors live in ``test_otp_vectors``; here we cover validation,
normalisation, verification windows, and the helper functions.
"""

import base64
from datetime import datetime, timezone

import pytest

from vaultforge.otp import (
    Algorithm,
    OTPError,
    generate_code,
    generate_secret,
    normalize_secret,
    provisioning_uri,
    time_remaining,
    verify_code,
)

SECRET = base64.b32encode(b"12345678901234567890").decode()
FIXED_TIME = 1234567890


def test_generate_secret_default_length_and_alphabet():
    secret = generate_secret()
    assert len(secret) == 32
    assert secret == secret.upper()
    assert "=" not in secret
    # Round-trips as base32, i.e. 20 bytes of entropy.
    assert len(base64.b32decode(secret + "=" * (-len(secret) % 8))) == 20


def test_generate_secret_is_unique_per_call():
    assert generate_secret() != generate_secret()


@pytest.mark.parametrize("num_bytes", [0, 1, 19, 129, 4096])
def test_generate_secret_rejects_out_of_range(num_bytes):
    with pytest.raises(OTPError):
        generate_secret(num_bytes)


def test_generate_secret_accepts_custom_size():
    secret = generate_secret(32)
    assert len(base64.b32decode(secret + "=" * (-len(secret) % 8))) == 32


@pytest.mark.parametrize(
    "raw",
    [
        SECRET.lower(),
        SECRET + "====",
        " ".join(SECRET[i : i + 4] for i in range(0, len(SECRET), 4)),
        "-".join(SECRET[i : i + 4] for i in range(0, len(SECRET), 4)),
    ],
)
def test_normalize_secret_canonicalises_cosmetic_variants(raw):
    assert normalize_secret(raw) == SECRET


@pytest.mark.parametrize("raw", ["", "   ", "not base32!", "0189"])
def test_normalize_secret_rejects_invalid(raw):
    with pytest.raises(OTPError):
        normalize_secret(raw)


def test_generate_code_is_deterministic_for_fixed_time():
    first = generate_code(SECRET, for_time=FIXED_TIME)
    second = generate_code(SECRET, for_time=FIXED_TIME)
    assert first == second
    assert len(first) == 6
    assert first.isdigit()


def test_generate_code_accepts_aware_datetime():
    aware = datetime.fromtimestamp(FIXED_TIME, tz=timezone.utc)
    assert generate_code(SECRET, for_time=aware) == generate_code(SECRET, for_time=FIXED_TIME)


def test_generate_code_naive_datetime_treated_as_utc():
    naive = datetime(2009, 2, 13, 23, 31, 30)
    aware = naive.replace(tzinfo=timezone.utc)
    assert generate_code(SECRET, for_time=naive) == generate_code(SECRET, for_time=aware)


@pytest.mark.parametrize("digits", [6, 7, 8])
def test_generate_code_supported_digit_lengths(digits):
    assert len(generate_code(SECRET, digits=digits, for_time=FIXED_TIME)) == digits


@pytest.mark.parametrize("digits", [0, 5, 9, 10])
def test_generate_code_rejects_unsupported_digits(digits):
    with pytest.raises(OTPError):
        generate_code(SECRET, digits=digits, for_time=FIXED_TIME)


@pytest.mark.parametrize("period", [0, -1, 3601])
def test_generate_code_rejects_out_of_range_period(period):
    with pytest.raises(OTPError):
        generate_code(SECRET, period=period, for_time=FIXED_TIME)


def test_algorithms_produce_different_codes():
    codes = {
        algorithm: generate_code(SECRET, algorithm=algorithm, for_time=FIXED_TIME)
        for algorithm in Algorithm
    }
    assert len(set(codes.values())) == len(Algorithm)


def test_verify_code_accepts_the_generated_code():
    code = generate_code(SECRET, for_time=FIXED_TIME)
    assert verify_code(SECRET, code, for_time=FIXED_TIME) is True


def test_verify_code_rejects_a_wrong_code():
    assert verify_code(SECRET, "000000", for_time=FIXED_TIME) is False


def test_verify_code_empty_string_is_false():
    assert verify_code(SECRET, "   ", for_time=FIXED_TIME) is False


def test_verify_code_window_tolerates_clock_skew():
    code = generate_code(SECRET, for_time=FIXED_TIME)
    assert verify_code(SECRET, code, for_time=FIXED_TIME + 30, valid_window=0) is False
    assert verify_code(SECRET, code, for_time=FIXED_TIME + 30, valid_window=1) is True


@pytest.mark.parametrize("window", [-1, 11])
def test_verify_code_rejects_out_of_range_window(window):
    with pytest.raises(OTPError):
        verify_code(SECRET, "000000", valid_window=window)


def test_verify_code_rejects_non_string_code():
    with pytest.raises(OTPError):
        verify_code(SECRET, None)  # type: ignore[arg-type]


def test_time_remaining_is_within_the_period():
    remaining = time_remaining(30, for_time=FIXED_TIME)
    assert 1 <= remaining <= 30


def test_time_remaining_at_boundary_is_full_period():
    assert time_remaining(30, for_time=0.0) == 30
    assert time_remaining(30, for_time=30.0) == 30


def test_time_remaining_counts_down_between_boundaries():
    assert time_remaining(30, for_time=15.0) == 15


def test_time_remaining_rejects_bad_period():
    with pytest.raises(OTPError):
        time_remaining(0)


def test_provisioning_uri_contains_secret_and_labels():
    uri = provisioning_uri(SECRET, name="alice@example.com", issuer="ACME")
    assert uri.startswith("otpauth://totp/")
    assert f"secret={SECRET}" in uri
    assert "issuer=ACME" in uri
    assert "alice%40example.com" in uri


def test_provisioning_uri_without_issuer():
    uri = provisioning_uri(SECRET, name="alice@example.com")
    assert "issuer=" not in uri


def test_provisioning_uri_requires_name():
    with pytest.raises(OTPError):
        provisioning_uri(SECRET, name="")


def test_provisioning_uri_reflects_digits_and_period():
    uri = provisioning_uri(SECRET, name="a@b.c", digits=8, period=60)
    assert "digits=8" in uri
    assert "period=60" in uri


def test_missing_pyotp_raises_actionable_error(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "pyotp":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(OTPError, match="vaultforge\\[otp\\]"):
        generate_code(SECRET)
