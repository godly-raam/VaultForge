"""Safe filesystem handling for vault files.

New destinations use an atomic no-clobber hard-link commit. Existing vaults are
replaced only by the locked, snapshot-checked atomic replacement path below.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .errors import (
    ConcurrentModificationError,
    DestinationExistsError,
    InvalidVaultError,
    UnsupportedFilesystemError,
)
from .format import MAX_FILE_LEN, check_file_size

__all__ = [
    "VaultSnapshot",
    "ensure_parent_directory",
    "insecure_permissions",
    "read_vault_bytes",
    "read_vault_snapshot",
    "vault_lock",
    "write_new_vault",
    "write_updated_vault",
]

_TEMP_PREFIX = ".vaultforge-"
_TEMP_SUFFIX = ".tmp"
_NO_LINK_ERRNOS = frozenset(
    code
    for code in (
        getattr(errno, "EPERM", None),
        getattr(errno, "EOPNOTSUPP", None),
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "ENOSYS", None),
        getattr(errno, "EMLINK", None),
        getattr(errno, "EXDEV", None),
    )
    if code is not None
)
_HARDLINK_UNSUPPORTED_MESSAGE = (
    "this filesystem does not support hard links, which VaultForge requires to "
    "create a vault without risking overwriting an existing file; choose a "
    "filesystem that supports hard links rather than one that does not"
)


@dataclass(frozen=True)
class VaultSnapshot:
    """Identity and contents used to detect modifications before replacement."""

    data: bytes
    device: int
    inode: int
    size: int
    mtime_ns: int
    digest: bytes


def ensure_parent_directory(path: Path) -> None:
    """Create the vault's parent directory (mode 0700) if it does not exist."""
    os.makedirs(path.parent, mode=0o700, exist_ok=True)


@contextmanager
def vault_lock(path: Path) -> Iterator[None]:
    """Serialize VaultForge writers using a persistent sibling lock file."""
    lock_path = path.with_name(f".{path.name}.lock")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        if os.name == "nt":
            import msvcrt

            windows_crt = cast(Any, msvcrt)
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            windows_crt.locking(fd, windows_crt.LK_LOCK, 1)
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                windows_crt.locking(fd, windows_crt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _snapshot_from_fd(fd: int, path: Path) -> VaultSnapshot:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise InvalidVaultError("vault path is not a regular file")
    check_file_size(before.st_size)
    chunks: list[bytes] = []
    remaining = MAX_FILE_LEN + 1
    while remaining:
        chunk = os.read(fd, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    after = os.fstat(fd)
    check_file_size(len(data))
    try:
        current = path.stat()
    except OSError as exc:
        raise ConcurrentModificationError("vault changed while it was being read") from exc
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or current.st_dev != after.st_dev
        or current.st_ino != after.st_ino
    ):
        raise ConcurrentModificationError("vault changed while it was being read")
    return VaultSnapshot(
        data=data,
        device=after.st_dev,
        inode=after.st_ino,
        size=after.st_size,
        mtime_ns=after.st_mtime_ns,
        digest=hashlib.sha256(data).digest(),
    )


def read_vault_snapshot(path: Path) -> VaultSnapshot:
    """Read a bounded vault and capture an identity token for compare-and-swap."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        return _snapshot_from_fd(fd, path)
    finally:
        os.close(fd)


def read_vault_bytes(path: Path) -> bytes:
    """Read a vault file with a size gate before and after the bounded read."""
    return read_vault_snapshot(path).data


def _matches_snapshot(path: Path, snapshot: VaultSnapshot) -> bool:
    try:
        current = read_vault_snapshot(path)
    except OSError:
        return False
    return (
        current.device == snapshot.device
        and current.inode == snapshot.inode
        and current.size == snapshot.size
        and current.mtime_ns == snapshot.mtime_ns
        and current.digest == snapshot.digest
    )


def _write_temp(path: Path, data: bytes) -> Path:
    if len(data) > MAX_FILE_LEN:
        raise ValueError(f"vault file exceeds the maximum size of {MAX_FILE_LEN} bytes")
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=_TEMP_PREFIX, suffix=_TEMP_SUFFIX)
    tmp_path = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        _silent_unlink(tmp_path)
        raise
    return tmp_path


def write_new_vault(path: Path, data: bytes) -> None:
    """Atomically create ``path`` without replacing an existing destination."""
    tmp_path = _write_temp(path, data)
    try:
        _commit_no_clobber(tmp_path, path)
    finally:
        _silent_unlink(tmp_path)
    _fsync_directory(path.parent)


def write_updated_vault(path: Path, data: bytes, snapshot: VaultSnapshot) -> None:
    """Atomically replace a vault only if its previously-read snapshot matches."""
    tmp_path = _write_temp(path, data)
    try:
        if not _matches_snapshot(path, snapshot):
            raise ConcurrentModificationError("vault changed before the update could be committed")
        os.replace(tmp_path, path)
        _fsync_directory(path.parent)
    finally:
        _silent_unlink(tmp_path)


def insecure_permissions(path: Path) -> bool:
    """Return whether group or other permission bits are set (POSIX only)."""
    if os.name != "posix":
        return False
    mode = stat.S_IMODE(os.stat(path).st_mode)
    return bool(mode & 0o077)


def _commit_no_clobber(tmp_path: Path, target: Path) -> None:
    """Publish a new file by hard link; this cannot replace an existing path."""
    try:
        os.link(tmp_path, target)
    except FileExistsError as exc:
        raise DestinationExistsError(f"refusing to overwrite existing file: {target}") from exc
    except OSError as exc:
        if exc.errno in _NO_LINK_ERRNOS:
            raise UnsupportedFilesystemError(_HARDLINK_UNSUPPORTED_MESSAGE) from exc
        raise


def _silent_unlink(path: Path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _fsync_directory(directory: Path) -> None:
    """Best-effort durability of a directory entry (not supported everywhere)."""
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
