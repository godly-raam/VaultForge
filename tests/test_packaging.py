"""Packaging and invocation tests.

These verify the *installed* package: distribution metadata, the console-script
entry point, bundled data loading, and that ``python -m vaultforge`` works even
when the current directory is unrelated to the source tree.
"""

import importlib.metadata as metadata
import subprocess
import sys

import pytest

from vaultforge import __version__
from vaultforge.wordlist import load_wordlist


def _distribution():
    try:
        return metadata.distribution("vaultforge")
    except metadata.PackageNotFoundError:  # pragma: no cover - only when not installed
        pytest.skip("vaultforge is not installed in this environment")


def test_distribution_version_matches_package_version():
    dist = _distribution()
    assert dist.version == __version__


def test_console_script_entry_point_is_registered():
    dist = _distribution()
    entry_points = {(ep.group, ep.name): ep.value for ep in dist.entry_points}
    assert entry_points.get(("console_scripts", "vaultforge")) == "vaultforge.cli:app"


def test_wordlist_is_loadable_from_installed_package():
    words = load_wordlist()
    assert len(words) >= 1296


def test_otp_optional_extra_is_declared():
    dist = _distribution()
    assert "otp" in (dist.metadata.get_all("Provides-Extra") or [])


def test_cryptography_runtime_dependency_is_declared():
    dist = _distribution()
    requires = dist.requires or []
    assert any(req.startswith("cryptography") for req in requires)


def test_module_invocation_works_outside_source_tree(tmp_path):
    completed = subprocess.run(
        [sys.executable, "-m", "vaultforge", "--version"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0
    assert "vaultforge" in completed.stdout.lower()
