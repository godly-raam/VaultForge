"""Tests for vault initialization and unlocking (format v1 service layer)."""

from pathlib import Path

import pytest

from vaultforge.vault import crypto, service, store
from vaultforge.vault import format as fmt
from vaultforge.vault.errors import (
    AUTH_ERROR_MESSAGE,
    AuthError,
    CorruptPayloadError,
    DestinationExistsError,
    InvalidVaultError,
    NotAVaultError,
    UnsupportedVersionError,
)

PASSWORD = b"correct horse battery staple"
EMPTY_VAULT = {"schema": 1, "entries": []}


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    """One real vault, reused read-only by the unlock-tampering tests."""
    path = tmp_path_factory.mktemp("sample") / "vault.vf"
    header = service.initialize_vault(path, PASSWORD)
    return {"bytes": path.read_bytes(), "header": header}


def _write_vault(tmp_path, data):
    path = tmp_path / "vault.vf"
    path.write_bytes(data)
    return path


def test_initialize_creates_a_v1_vault_with_an_empty_payload(tmp_path):
    path = tmp_path / "vault.vf"
    header = service.initialize_vault(path, PASSWORD)

    assert header.format_version == fmt.FORMAT_VERSION
    assert header.memory_kib == 65536
    assert header.iterations == 3
    assert header.lanes == 1
    assert len(header.vault_id) == fmt.VAULT_ID_LEN
    # 122-byte header + 25-byte empty payload + 16-byte tag.
    assert path.stat().st_size == 163
    assert service.unlock_vault(path, PASSWORD) == EMPTY_VAULT


def test_default_vault_path_under_the_home_directory():
    assert service.default_vault_path() == Path.home() / ".vaultforge" / "vault.vf"


def test_empty_vault_is_a_fresh_object_each_call():
    first = service.empty_vault()
    second = service.empty_vault()
    assert first == EMPTY_VAULT
    assert first is not second
    first["entries"].append({"x": 1})
    assert second["entries"] == []


def test_initialize_refuses_an_existing_destination_without_touching_it(tmp_path):
    path = tmp_path / "vault.vf"
    path.write_bytes(b"precious existing bytes")
    with pytest.raises(DestinationExistsError):
        service.initialize_vault(path, PASSWORD)
    assert path.read_bytes() == b"precious existing bytes"


def test_initialize_creates_the_parent_directory(tmp_path):
    path = tmp_path / "nested" / "dir" / "vault.vf"
    service.initialize_vault(path, PASSWORD)
    assert path.parent.is_dir()


def test_unlock_with_the_wrong_password_is_an_auth_error(sample, tmp_path):
    path = _write_vault(tmp_path, sample["bytes"])
    with pytest.raises(AuthError) as excinfo:
        service.unlock_vault(path, b"the wrong password")
    assert str(excinfo.value) == AUTH_ERROR_MESSAGE


def test_unlock_detects_a_tampered_wrapped_key(sample, tmp_path):
    data = bytearray(sample["bytes"])
    data[80] ^= 0x01  # inside the wrapped key (offsets 74..122)
    path = _write_vault(tmp_path, bytes(data))
    with pytest.raises(AuthError):
        service.unlock_vault(path, PASSWORD)


def test_unlock_detects_a_tampered_body(sample, tmp_path):
    data = bytearray(sample["bytes"])
    data[-1] ^= 0x01  # inside the body ciphertext/tag
    path = _write_vault(tmp_path, bytes(data))
    with pytest.raises(AuthError):
        service.unlock_vault(path, PASSWORD)


def test_unlock_detects_a_tampered_salt(sample, tmp_path):
    data = bytearray(sample["bytes"])
    data[40] ^= 0x01  # inside the salt (offsets 34..50), which is in the wrap AAD
    path = _write_vault(tmp_path, bytes(data))
    with pytest.raises(AuthError):
        service.unlock_vault(path, PASSWORD)


def test_unlock_rejects_a_truncated_file(sample, tmp_path):
    path = _write_vault(tmp_path, sample["bytes"][:100])
    with pytest.raises(InvalidVaultError):
        service.unlock_vault(path, PASSWORD)


def test_unlock_rejects_a_non_vault(sample, tmp_path):
    path = _write_vault(tmp_path, b"XXXXX" + sample["bytes"][5:])
    with pytest.raises(NotAVaultError):
        service.unlock_vault(path, PASSWORD)


def test_unlock_rejects_an_unsupported_version(sample, tmp_path):
    data = bytearray(sample["bytes"])
    data[5] = 2
    path = _write_vault(tmp_path, bytes(data))
    with pytest.raises(UnsupportedVersionError):
        service.unlock_vault(path, PASSWORD)


def test_bad_kdf_parameters_are_rejected_before_argon2id(sample, tmp_path, monkeypatch):
    data = bytearray(sample["bytes"])
    data[22:26] = (4).to_bytes(4, "big")  # memory below the v1 minimum
    path = _write_vault(tmp_path, bytes(data))

    def boom(*args, **kwargs):  # pragma: no cover - only fires on a regression
        raise AssertionError("Argon2id must not run for an invalid header")

    monkeypatch.setattr(crypto, "Argon2id", boom)
    with pytest.raises(InvalidVaultError):
        service.unlock_vault(path, PASSWORD)


def test_unlock_does_not_modify_the_vault_file(sample, tmp_path):
    path = _write_vault(tmp_path, sample["bytes"])
    service.unlock_vault(path, PASSWORD)
    assert path.read_bytes() == sample["bytes"]


def test_a_payload_that_decrypts_but_is_not_valid_json_is_corrupt(tmp_path):
    # Build a genuine v1 vault whose body encrypts non-JSON text: a tag check
    # alone cannot produce this, so it exercises the CorruptPayloadError path.
    vault_id = bytes(range(16))
    salt = bytes(range(16, 32))
    wrap_nonce = bytes(range(12))
    body_nonce = bytes(range(12, 24))
    kek = crypto.derive_kek(PASSWORD, salt)
    dek = bytes(range(32))

    prefix = fmt.build_header_prefix(
        vault_id=vault_id, salt=salt, wrap_nonce=wrap_nonce, body_nonce=body_nonce
    )
    wrapped_key = crypto.wrap_dek(kek, wrap_nonce, dek, aad=fmt.wrap_aad(prefix))
    header = fmt.assemble_header(prefix, wrapped_key)
    body = crypto.encrypt_body(dek, body_nonce, b"this is not json", aad=fmt.body_aad(header))

    path = _write_vault(tmp_path, header + body)
    with pytest.raises(CorruptPayloadError):
        service.unlock_vault(path, PASSWORD)


def test_unicode_passwords_round_trip(tmp_path):
    path = tmp_path / "vault.vf"
    password = "p\u00e4ssw\u00f6rd-Kl\u00fcft".encode("utf-8")
    service.initialize_vault(path, password)
    assert service.unlock_vault(path, password) == EMPTY_VAULT
    with pytest.raises(AuthError):
        service.unlock_vault(path, "p\u00e4ssw\u00f6rd".encode("utf-8"))


def test_unlock_rejects_an_oversized_file(tmp_path, monkeypatch):
    # Shrink the cap instead of allocating 16 MiB; the size gate must still run
    # before any key derivation or body read.
    monkeypatch.setattr(fmt, "MAX_FILE_LEN", 150)
    monkeypatch.setattr(store, "MAX_FILE_LEN", 150)
    path = _write_vault(tmp_path, b"x" * 200)
    with pytest.raises(InvalidVaultError):
        service.unlock_vault(path, PASSWORD)


def test_initialize_leaves_no_partial_vault_when_the_commit_fails(tmp_path, monkeypatch):
    def boom(tmp, destination):  # pragma: no cover - only fires on a regression
        raise RuntimeError("commit failed")

    monkeypatch.setattr(store, "_commit_no_clobber", boom)
    path = tmp_path / "vault.vf"
    with pytest.raises(RuntimeError):
        service.initialize_vault(path, PASSWORD)
    # A failed init must not leave a destination (valid-looking or otherwise).
    assert not path.exists()
    assert list(tmp_path.glob(".vaultforge-*")) == []
