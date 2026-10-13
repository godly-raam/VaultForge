"""Tests for the v1 vault container format.

A golden fixture pins the exact 74-byte prefix and 122-byte header bytes so any
accidental layout change is caught. The negative tests cover every rejection the
format spec requires *before* the KDF runs.
"""

import pytest

from vaultforge.vault import crypto
from vaultforge.vault import format as fmt
from vaultforge.vault.errors import (
    CryptoParameterError,
    InvalidVaultError,
    NotAVaultError,
    UnsupportedVersionError,
)

VAULT_ID = bytes(range(16))
SALT = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
WRAP_NONCE = bytes.fromhex("000102030405060708090a0b")
BODY_NONCE = bytes.fromhex("0c0d0e0f1011121314151617")
WRAPPED_KEY = bytes(range(48))

GOLDEN_PREFIX_HEX = (
    "564c54464701000102030405060708090a0b0c0d0e0f000100000000000300000001"
    "0f1e2d3c4b5a69788796a5b4c3d2e1f0000102030405060708090a0b0c0d0e0f1011121314151617"
)
GOLDEN_HEADER_HEX = (
    "564c54464701000102030405060708090a0b0c0d0e0f000100000000000300000001"
    "0f1e2d3c4b5a69788796a5b4c3d2e1f0000102030405060708090a0b0c0d0e0f1011121314151617"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
)


def _prefix(**overrides):
    params = {
        "vault_id": VAULT_ID,
        "salt": SALT,
        "wrap_nonce": WRAP_NONCE,
        "body_nonce": BODY_NONCE,
    }
    params.update(overrides)
    return fmt.build_header_prefix(**params)


def _header(**overrides):
    return fmt.assemble_header(_prefix(**overrides), WRAPPED_KEY)


def test_container_constants_match_the_spec():
    assert fmt.MAGIC == b"VLTFG"
    assert fmt.FORMAT_VERSION == 1
    assert fmt.HEADER_PREFIX_LEN == 74
    assert fmt.WRAPPED_KEY_LEN == 48
    assert fmt.HEADER_LEN == 122
    assert fmt.MIN_FILE_LEN == 138
    assert fmt.MAX_FILE_LEN == 16 * 1024 * 1024


def test_golden_prefix_and_header_bytes():
    prefix = _prefix()
    assert len(prefix) == fmt.HEADER_PREFIX_LEN
    assert prefix.hex() == GOLDEN_PREFIX_HEX

    header = fmt.assemble_header(prefix, WRAPPED_KEY)
    assert len(header) == fmt.HEADER_LEN
    assert header.hex() == GOLDEN_HEADER_HEX


def test_header_fields_land_at_the_documented_offsets():
    header = _header()
    assert header[0:5] == fmt.MAGIC
    assert header[5] == fmt.FORMAT_VERSION
    assert header[6:22] == VAULT_ID
    assert int.from_bytes(header[22:26], "big") == 65536
    assert int.from_bytes(header[26:30], "big") == 3
    assert int.from_bytes(header[30:34], "big") == 1
    assert header[34:50] == SALT
    assert header[50:62] == WRAP_NONCE
    assert header[62:74] == BODY_NONCE
    assert header[74:122] == WRAPPED_KEY


def test_parse_header_round_trips_a_built_header():
    parsed = fmt.parse_header(_header())
    assert parsed.format_version == fmt.FORMAT_VERSION
    assert parsed.vault_id == VAULT_ID
    assert parsed.memory_kib == 65536
    assert parsed.iterations == 3
    assert parsed.lanes == 1
    assert parsed.salt == SALT
    assert parsed.wrap_nonce == WRAP_NONCE
    assert parsed.body_nonce == BODY_NONCE
    assert parsed.wrapped_key == WRAPPED_KEY


def test_aad_slices_exclude_and_include_the_wrapped_key():
    header = _header()
    full_file = header + b"\x00" * (fmt.TAG_LEN + 32)  # header + body ciphertext
    assert fmt.wrap_aad(full_file) == header[:74]
    assert fmt.body_aad(full_file) == header[:122]
    # The wrap AAD stops before the wrapped key; the body AAD includes it.
    assert fmt.wrap_aad(full_file) == fmt.wrap_aad(header)
    assert fmt.body_aad(full_file) == header


def test_parse_header_never_runs_argon2id(monkeypatch):
    def boom(*args, **kwargs):  # pragma: no cover - only fires on a regression
        raise AssertionError("Argon2id must not run while parsing a header")

    monkeypatch.setattr(crypto, "Argon2id", boom)
    # A valid header parses...
    assert fmt.parse_header(_header()).vault_id == VAULT_ID
    # ...and an out-of-range one is rejected, both without touching Argon2id.
    with pytest.raises(InvalidVaultError):
        fmt.parse_header(_header(memory_kib=4))


# --- size gate --------------------------------------------------------------


def test_check_file_size_accepts_the_boundary_values():
    fmt.check_file_size(fmt.MIN_FILE_LEN)
    fmt.check_file_size(fmt.MAX_FILE_LEN)


@pytest.mark.parametrize("size", [0, 1, fmt.MIN_FILE_LEN - 1, fmt.MAX_FILE_LEN + 1])
def test_check_file_size_rejects_out_of_range_sizes(size):
    with pytest.raises(InvalidVaultError):
        fmt.check_file_size(size)


def test_parse_header_rejects_a_truncated_header():
    with pytest.raises(InvalidVaultError):
        fmt.parse_header(b"VLTFG")


# --- structural rejections --------------------------------------------------


def test_bad_magic_is_not_a_vault():
    with pytest.raises(NotAVaultError):
        fmt.parse_header(b"XXXXX" + _header()[5:])


@pytest.mark.parametrize("version", [0, 2, 255])
def test_unknown_version_is_rejected(version):
    data = bytearray(_header())
    data[5] = version
    with pytest.raises(UnsupportedVersionError):
        fmt.parse_header(bytes(data))


@pytest.mark.parametrize(
    ("memory_kib", "iterations", "lanes"),
    [
        (4, 3, 1),  # memory below minimum
        (8, 3, 4),  # memory < 8 * lanes
        (2_000_000, 3, 1),  # memory above maximum
        (65536, 0, 1),  # iterations too low
        (65536, 11, 1),  # iterations too high
        (65536, 3, 0),  # lanes too low
        (65536, 3, 5),  # lanes too high
        (32768, 3, 1),  # in range but not the pinned v1 profile
        (65536, 4, 1),  # in range but not the pinned v1 profile
    ],
)
def test_out_of_range_or_non_v1_kdf_params_are_rejected(memory_kib, iterations, lanes):
    with pytest.raises(InvalidVaultError):
        fmt.parse_header(_header(memory_kib=memory_kib, iterations=iterations, lanes=lanes))


# --- builder argument validation --------------------------------------------


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("vault_id", b"\x00" * 15),
        ("salt", b"\x00" * 8),
        ("wrap_nonce", b"\x00" * 11),
        ("body_nonce", b"\x00" * 13),
    ],
)
def test_build_header_prefix_rejects_mis_sized_fields(name, value):
    with pytest.raises(CryptoParameterError):
        _prefix(**{name: value})


def test_assemble_header_rejects_mis_sized_inputs():
    with pytest.raises(CryptoParameterError):
        fmt.assemble_header(b"\x00" * 10, WRAPPED_KEY)
    with pytest.raises(CryptoParameterError):
        fmt.assemble_header(_prefix(), b"\x00" * 16)


def test_generate_vault_id_is_16_bytes_and_does_not_repeat():
    first = fmt.generate_vault_id()
    assert len(first) == fmt.VAULT_ID_LEN
    assert first != fmt.generate_vault_id()
