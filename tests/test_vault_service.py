"""Tests for vault initialization and unlocking (format v1 service layer)."""

import os
import stat
import threading
from pathlib import Path

import pytest

from vaultforge.vault import crypto, service, store
from vaultforge.vault import format as fmt
from vaultforge.vault.errors import (
    AUTH_ERROR_MESSAGE,
    AuthError,
    CorruptPayloadError,
    DestinationExistsError,
    DuplicateEntryError,
    EntryNotFoundError,
    InvalidVaultError,
    NotAVaultError,
    PayloadValidationError,
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


def _entry(entry_id):
    return {
        "id": entry_id,
        "type": "note",
        "title": entry_id,
        "tags": [],
        "created_at": 1,
        "updated_at": 1,
        "fields": {"body": "persisted"},
    }


def test_add_entry_persists_with_stable_id_distinct_from_title(tmp_path):
    path = tmp_path / "vault.vf"
    service.initialize_vault(path, PASSWORD)

    created = service.add_entry(
        path,
        PASSWORD,
        entry_type="login",
        title="Work",
        fields={"username": "alice", "password": "test-secret"},
    )

    persisted = service.get_entry(path, PASSWORD, created["id"])
    assert persisted == created
    assert created["id"] != created["title"]
    assert len(created["id"]) == 32
    assert b"test-secret" not in path.read_bytes()


def test_add_entry_rejects_duplicate_id_without_changing_vault(tmp_path, monkeypatch):
    path = tmp_path / "vault.vf"
    service.initialize_vault(path, PASSWORD)
    monkeypatch.setattr(service.secrets, "token_hex", lambda length: "a" * 32)
    service.add_entry(path, PASSWORD, entry_type="note", title="First", fields={"body": "one"})
    before = path.read_bytes()

    with pytest.raises(DuplicateEntryError):
        service.add_entry(path, PASSWORD, entry_type="note", title="Second", fields={"body": "two"})

    assert path.read_bytes() == before


def test_list_entries_and_get_entry_are_persisted_reads(tmp_path):
    path = tmp_path / "vault.vf"
    service.initialize_vault(path, PASSWORD)
    entry = service.add_entry(
        path, PASSWORD, entry_type="note", title="Memo", fields={"body": "private"}
    )

    assert service.list_entries(path, PASSWORD) == [entry]
    assert service.get_entry(path, PASSWORD, entry["id"]) == entry
    with pytest.raises(EntryNotFoundError):
        service.get_entry(path, PASSWORD, "f" * 32)


def test_update_entry_preserves_id_and_unmodified_fields_when_renaming(tmp_path):
    path = tmp_path / "vault.vf"
    service.initialize_vault(path, PASSWORD)
    entry = service.add_entry(
        path,
        PASSWORD,
        entry_type="login",
        title="Old title",
        fields={"username": "alice", "password": "private", "url": "https://example.test"},
    )

    service.update_entry(
        path, PASSWORD, entry["id"], title="New title", fields={"password": "changed"}
    )

    updated = service.get_entry(path, PASSWORD, entry["id"])
    assert updated["id"] == entry["id"]
    assert updated["title"] == "New title"
    assert updated["fields"] == {
        "username": "alice",
        "password": "changed",
        "url": "https://example.test",
    }
    assert updated["created_at"] == entry["created_at"]


def test_update_entry_rejects_missing_id_and_invalid_fields_without_writing(tmp_path):
    path = tmp_path / "vault.vf"
    service.initialize_vault(path, PASSWORD)
    entry = service.add_entry(
        path, PASSWORD, entry_type="note", title="Memo", fields={"body": "safe"}
    )
    before = path.read_bytes()

    with pytest.raises(EntryNotFoundError):
        service.update_entry(path, PASSWORD, "f" * 32, title="Missing")
    with pytest.raises(PayloadValidationError):
        service.update_entry(path, PASSWORD, entry["id"], fields={"unknown": "private"})
    with pytest.raises(PayloadValidationError):
        service.update_entry(path, PASSWORD, entry["id"], fields={"body": "x" * 65_537})

    assert path.read_bytes() == before


def test_delete_entry_persists_and_rejects_missing_id(tmp_path):
    path = tmp_path / "vault.vf"
    service.initialize_vault(path, PASSWORD)
    entry = service.add_entry(
        path, PASSWORD, entry_type="note", title="Memo", fields={"body": "safe"}
    )

    service.delete_entry(path, PASSWORD, entry["id"])

    assert service.list_entries(path, PASSWORD) == []
    with pytest.raises(EntryNotFoundError):
        service.delete_entry(path, PASSWORD, entry["id"])


def test_crud_mutations_reject_wrong_password_without_changing_vault(tmp_path):
    path = tmp_path / "vault.vf"
    service.initialize_vault(path, PASSWORD)
    entry = service.add_entry(
        path, PASSWORD, entry_type="note", title="Memo", fields={"body": "safe"}
    )
    before = path.read_bytes()

    with pytest.raises(AuthError):
        service.update_entry(path, b"wrong", entry["id"], title="Not changed")
    with pytest.raises(AuthError):
        service.delete_entry(path, b"wrong", entry["id"])

    assert path.read_bytes() == before


def test_update_vault_persists_encrypted_payload_with_fresh_key_and_nonces(tmp_path):
    path = tmp_path / "vault.vf"
    service.initialize_vault(path, PASSWORD)
    before = path.read_bytes()

    service.update_vault(path, PASSWORD, lambda payload: {**payload, "entries": [_entry("a" * 32)]})

    after = path.read_bytes()
    assert after != before
    old_header = fmt.parse_header(before)
    new_header = fmt.parse_header(after)
    assert new_header.vault_id == old_header.vault_id
    assert new_header.salt == old_header.salt
    assert new_header.wrap_nonce != old_header.wrap_nonce
    assert new_header.body_nonce != old_header.body_nonce
    assert new_header.wrapped_key != old_header.wrapped_key
    assert service.unlock_vault(path, PASSWORD)["entries"] == [_entry("a" * 32)]
    assert b"persisted" not in after


def test_update_vault_wrong_password_preserves_original(tmp_path):
    path = tmp_path / "vault.vf"
    service.initialize_vault(path, PASSWORD)
    before = path.read_bytes()

    with pytest.raises(AuthError):
        service.update_vault(path, b"incorrect", lambda payload: payload)

    assert path.read_bytes() == before
    assert list(tmp_path.glob(".vaultforge-*")) == []


def test_update_vault_invalid_payload_preserves_original(tmp_path):
    path = tmp_path / "vault.vf"
    service.initialize_vault(path, PASSWORD)
    before = path.read_bytes()

    with pytest.raises(PayloadValidationError):
        service.update_vault(path, PASSWORD, lambda payload: {"schema": 1, "entries": [{}]})

    assert path.read_bytes() == before
    assert list(tmp_path.glob(".vaultforge-*")) == []


def test_update_vault_replace_failure_preserves_original_and_cleans_temp(tmp_path, monkeypatch):
    path = tmp_path / "vault.vf"
    service.initialize_vault(path, PASSWORD)
    before = path.read_bytes()

    def fail_replace(source, destination):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(store.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        service.update_vault(
            path, PASSWORD, lambda payload: {**payload, "entries": [_entry("b" * 32)]}
        )

    assert path.read_bytes() == before
    assert list(tmp_path.glob(".vaultforge-*")) == []


def test_concurrent_additions_are_serialized_without_lost_entries(tmp_path):
    path = tmp_path / "vault.vf"
    service.initialize_vault(path, PASSWORD)
    barrier = threading.Barrier(2)
    errors = []

    def add(title):
        try:
            barrier.wait(timeout=10)
            service.add_entry(
                path, PASSWORD, entry_type="note", title=title, fields={"body": title}
            )
        except Exception as exc:  # surfaced in the main test thread
            errors.append(exc)

    first = threading.Thread(target=add, args=("First",))
    second = threading.Thread(target=add, args=("Second",))
    first.start()
    second.start()
    first.join(timeout=30)
    second.join(timeout=30)

    assert not first.is_alive() and not second.is_alive()
    assert errors == []
    assert {entry["title"] for entry in service.list_entries(path, PASSWORD)} == {"First", "Second"}


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_update_vault_replacement_keeps_private_file_permissions(tmp_path):
    path = tmp_path / "vault.vf"
    service.initialize_vault(path, PASSWORD)

    service.update_vault(path, PASSWORD, lambda payload: payload)

    assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0
    lock_path = path.with_name(f".{path.name}.lock")
    assert stat.S_IMODE(lock_path.stat().st_mode) & 0o077 == 0


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
