"""Safe filesystem handling for vault files.

This layer owns the parts of the design that touch the disk and nothing else: it
does not know about keys or payloads. It exists to make two promises hold even
under crashes and concurrent writers:

* **Reads are bounded.** The size gate runs against ``os.stat`` before a single
  byte is read, and the read itself is capped, so pointing VaultForge at a
  gigantic or truncated file cannot exhaust memory.
* **New destinations are never clobbered.** A brand-new vault is written to a
  private temp file in the destination directory and published with ``os.link``,
  which fails atomically if the destination already exists. Two concurrent
  initializations cannot both succeed, and an existing file is never overwritten
  (not even partially). Where the filesystem cannot hard-link, the write fails
  safely rather than weakening the guarantee. Temp files are cleaned up on every
  failure path.

The exact procedure is specified in ``docs/VAULT_FORMAT.md`` section 8.
"""

from __future__ import annotations

import errno
import os
import stat
import tempfile
from pathlib import Path

from .errors import DestinationExistsError, UnsupportedFilesystemError
from .format import MAX_FILE_LEN, check_file_size

__all__ = [
    "ensure_parent_directory",
    "insecure_permissions",
    "read_vault_bytes",
    "write_new_vault",
]

# Temp file naming: hidden and obviously ours, in the destination directory so
# the final commit is a same-filesystem (atomic) operation.
_TEMP_PREFIX = ".vaultforge-"
_TEMP_SUFFIX = ".tmp"

# Errnos that mean "this filesystem cannot hardlink". Hard linking is the only
# commit mechanism; if it is unavailable we fail safely rather than weaken the
# no-clobber guarantee. Anything outside this set is a real error and re-raised.
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
    "filesystem that supports hard links (for example ext4, xfs, apfs, or ntfs) "
    "rather than one that does not (for example FAT/exFAT or some network mounts)"
)


def ensure_parent_directory(path: Path) -> None:
    """Create the vault's parent directory (mode 0700) if it does not exist."""
    os.makedirs(path.parent, mode=0o700, exist_ok=True)


def read_vault_bytes(path: Path) -> bytes:
    """Read a vault file, enforcing the size gate before and after the read.

    The pre-read ``os.stat`` gate avoids allocating for an oversized file; the
    post-read re-check closes the race where the file grows between the two.
    """
    check_file_size(path.stat().st_size)
    with open(path, "rb") as handle:
        data = handle.read(MAX_FILE_LEN + 1)
    check_file_size(len(data))
    return data


def write_new_vault(path: Path, data: bytes) -> None:
    """Atomically create ``path`` with ``data``, refusing to overwrite it.

    Raises :class:`DestinationExistsError` if ``path`` already exists, leaving
    it byte-for-byte untouched. The temp file is removed on every path.
    """
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=_TEMP_PREFIX, suffix=_TEMP_SUFFIX)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _commit_no_clobber(tmp_path, path)
    finally:
        _silent_unlink(tmp_path)
    _fsync_directory(path.parent)


def insecure_permissions(path: Path) -> bool:
    """Return whether group or other permission bits are set (POSIX only).

    Always ``False`` where the notion does not apply; Windows ACLs are not
    modelled here.
    """
    if os.name != "posix":
        return False
    mode = stat.S_IMODE(os.stat(path).st_mode)
    return bool(mode & 0o077)


def _commit_no_clobber(tmp_path: Path, target: Path) -> None:
    """Publish ``tmp_path`` as ``target`` without ever replacing an existing file.

    ``os.link`` fails atomically with ``EEXIST`` when ``target`` already exists,
    so an existing file is preserved byte-for-byte and two concurrent writers
    cannot both succeed. The temp file is removed by the caller's ``finally``.

    Hard links are the *only* commit primitive: where the filesystem cannot
    provide them, this raises :class:`UnsupportedFilesystemError` instead of
    falling back to a copy or rename that a crash could leave partial.
    """
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
    """Best-effort durability of the directory entry itself.

    Opening and fsyncing a directory is not portable (it fails on Windows), so
    failures here are ignored rather than surfaced.
    """
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
