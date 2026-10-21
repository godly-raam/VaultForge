"""Tests for the vault filesystem layer (bounded reads, no-clobber writes)."""

import errno
import os
import stat
import threading

import pytest

from vaultforge.vault import store
from vaultforge.vault.errors import (
    ConcurrentModificationError,
    DestinationExistsError,
    InvalidVaultError,
    UnsupportedFilesystemError,
)

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")


def _temp_files(directory):
    return sorted(path.name for path in directory.glob(".vaultforge-*"))


def test_write_new_vault_creates_the_file_with_its_exact_bytes(tmp_path):
    target = tmp_path / "vault.vf"
    store.write_new_vault(target, b"some bytes")
    assert target.read_bytes() == b"some bytes"
    assert _temp_files(tmp_path) == []


def test_write_updated_vault_atomically_replaces_matching_snapshot(tmp_path):
    target = tmp_path / "vault.vf"
    target.write_bytes(b"o" * 200)
    snapshot = store.read_vault_snapshot(target)

    store.write_updated_vault(target, b"n" * 200, snapshot)

    assert target.read_bytes() == b"n" * 200
    assert _temp_files(tmp_path) == []


def test_write_updated_vault_rejects_a_stale_snapshot(tmp_path):
    target = tmp_path / "vault.vf"
    target.write_bytes(b"o" * 200)
    snapshot = store.read_vault_snapshot(target)
    target.write_bytes(b"e" * 200)

    with pytest.raises(ConcurrentModificationError):
        store.write_updated_vault(target, b"r" * 200, snapshot)
    assert target.read_bytes() == b"e" * 200
    assert _temp_files(tmp_path) == []


def test_write_updated_vault_write_failure_preserves_target_and_cleans_temp(tmp_path, monkeypatch):
    target = tmp_path / "vault.vf"
    target.write_bytes(b"o" * 200)
    snapshot = store.read_vault_snapshot(target)

    def broken_replace(source, destination):
        raise OSError(errno.EIO, "simulated replacement failure")

    monkeypatch.setattr(store.os, "replace", broken_replace)
    with pytest.raises(OSError):
        store.write_updated_vault(target, b"r" * 200, snapshot)
    assert target.read_bytes() == b"o" * 200
    assert _temp_files(tmp_path) == []


def test_write_updated_vault_temp_write_failure_preserves_target_and_cleans_temp(
    tmp_path, monkeypatch
):
    target = tmp_path / "vault.vf"
    target.write_bytes(b"o" * 200)
    snapshot = store.read_vault_snapshot(target)
    monkeypatch.setattr(store.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("fail")))

    with pytest.raises(OSError, match="fail"):
        store.write_updated_vault(target, b"r" * 200, snapshot)
    assert target.read_bytes() == b"o" * 200
    assert _temp_files(tmp_path) == []


def test_write_updated_vault_rejects_oversized_data_before_writing(tmp_path, monkeypatch):
    target = tmp_path / "vault.vf"
    target.write_bytes(b"o" * 200)
    snapshot = store.read_vault_snapshot(target)
    monkeypatch.setattr(store, "MAX_FILE_LEN", 250)

    with pytest.raises(ValueError, match="maximum size"):
        store.write_updated_vault(target, b"x" * 251, snapshot)
    assert target.read_bytes() == b"o" * 200
    assert _temp_files(tmp_path) == []


def test_write_new_vault_refuses_to_overwrite(tmp_path):
    target = tmp_path / "vault.vf"
    target.write_bytes(b"original")
    with pytest.raises(DestinationExistsError):
        store.write_new_vault(target, b"replacement")
    assert target.read_bytes() == b"original"
    assert _temp_files(tmp_path) == []


def test_write_new_vault_is_atomic_for_concurrent_writers(tmp_path):
    target = tmp_path / "vault.vf"
    barrier = threading.Barrier(2)
    results = []

    def attempt(data):
        barrier.wait()
        try:
            store.write_new_vault(target, data)
            results.append(data)
        except DestinationExistsError:
            results.append(None)

    threads = [
        threading.Thread(target=attempt, args=(b"one",)),
        threading.Thread(target=attempt, args=(b"two",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    winners = [value for value in results if value is not None]
    assert len(winners) == 1
    assert target.read_bytes() == winners[0]
    assert _temp_files(tmp_path) == []


def test_write_new_vault_commit_failure_leaves_no_destination_or_temp(tmp_path, monkeypatch):
    target = tmp_path / "vault.vf"

    def boom(tmp, destination):  # pragma: no cover - only fires on a regression
        raise RuntimeError("commit failed")

    monkeypatch.setattr(store, "_commit_no_clobber", boom)
    with pytest.raises(RuntimeError):
        store.write_new_vault(target, b"data")
    assert not target.exists()
    assert _temp_files(tmp_path) == []


def test_write_new_vault_fails_safely_when_hardlinks_unavailable(tmp_path, monkeypatch):
    def no_link(source, destination):
        raise OSError(errno.EPERM, "hardlinks not supported")

    monkeypatch.setattr(store.os, "link", no_link)
    target = tmp_path / "vault.vf"
    with pytest.raises(UnsupportedFilesystemError):
        store.write_new_vault(target, b"portable")
    # Fail closed: no destination is created and the temp file is removed.
    assert not target.exists()
    assert _temp_files(tmp_path) == []


def test_write_new_vault_propagates_unexpected_link_errors(tmp_path, monkeypatch):
    def broken_link(source, destination):
        raise OSError(errno.ENOSPC, "no space left on device")

    monkeypatch.setattr(store.os, "link", broken_link)
    target = tmp_path / "vault.vf"
    with pytest.raises(OSError) as excinfo:
        store.write_new_vault(target, b"data")
    # An unrelated I/O error is not swallowed and is not mislabelled.
    assert excinfo.value.errno == errno.ENOSPC
    assert not target.exists()
    assert _temp_files(tmp_path) == []


def test_read_vault_bytes_returns_contents(tmp_path):
    path = tmp_path / "vault.vf"
    path.write_bytes(b"x" * 200)
    assert store.read_vault_bytes(path) == b"x" * 200


def test_read_vault_bytes_rejects_a_too_short_file(tmp_path):
    path = tmp_path / "vault.vf"
    path.write_bytes(b"short")
    with pytest.raises(InvalidVaultError):
        store.read_vault_bytes(path)


def test_read_vault_bytes_checks_size_before_and_after(tmp_path, monkeypatch):
    path = tmp_path / "vault.vf"
    path.write_bytes(b"x" * 200)
    seen = []

    def fake_check(size):
        seen.append(size)
        if len(seen) >= 2:
            raise InvalidVaultError("file grew during read")

    monkeypatch.setattr(store, "check_file_size", fake_check)
    with pytest.raises(InvalidVaultError):
        store.read_vault_bytes(path)
    # Gate once against os.stat, once against the bytes actually read.
    assert len(seen) == 2
    assert seen[0] == seen[1] == 200


def test_ensure_parent_directory_creates_nested_parents(tmp_path):
    target = tmp_path / "a" / "b" / "vault.vf"
    store.ensure_parent_directory(target)
    assert target.parent.is_dir()


@POSIX_ONLY
def test_ensure_parent_directory_is_private(tmp_path):
    target = tmp_path / "private" / "vault.vf"
    store.ensure_parent_directory(target)
    mode = stat.S_IMODE(target.parent.stat().st_mode)
    assert mode & 0o077 == 0


@POSIX_ONLY
def test_write_new_vault_creates_a_private_file(tmp_path):
    target = tmp_path / "vault.vf"
    store.write_new_vault(target, b"data")
    assert stat.S_IMODE(target.stat().st_mode) & 0o077 == 0


@POSIX_ONLY
def test_insecure_permissions_flags_group_or_other_access(tmp_path):
    target = tmp_path / "vault.vf"
    target.write_bytes(b"data")
    os.chmod(target, 0o600)
    assert store.insecure_permissions(target) is False
    os.chmod(target, 0o640)
    assert store.insecure_permissions(target) is True


def test_snapshot_from_fd_raises_concurrent_modification_if_path_disappears(tmp_path):
    from vaultforge.vault.errors import ConcurrentModificationError

    target = tmp_path / "vault.vf"
    store.write_new_vault(target, b"A" * 150)
    fd = os.open(target, os.O_RDONLY)
    try:
        target.unlink()
        with pytest.raises(
            ConcurrentModificationError, match="vault changed while it was being read"
        ):
            store._snapshot_from_fd(fd, target)
    finally:
        os.close(fd)
