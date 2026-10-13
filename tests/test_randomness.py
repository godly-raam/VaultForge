"""Tests asserting that all secret generation uses cryptographically secure
randomness from :mod:`secrets` and never the :mod:`random` module.
"""

import ast
import inspect

from vaultforge import generators


def _imported_modules(module) -> set:
    tree = ast.parse(inspect.getsource(module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    return imported


def test_generators_imports_secrets_but_not_random():
    imported = _imported_modules(generators)
    assert "secrets" in imported
    assert "random" not in imported


def test_generators_module_has_no_random_attribute():
    # If `random` were imported (even aliased) it would exist on the module.
    assert not hasattr(generators, "random")


def _spy_on(monkeypatch, name):
    real = getattr(generators.secrets, name)
    calls = {"count": 0}

    def spy(*args, **kwargs):
        calls["count"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(generators.secrets, name, spy)
    return calls


def test_password_uses_secrets_choice(monkeypatch):
    calls = _spy_on(monkeypatch, "choice")
    generators.generate_password(generators.PasswordPolicy(length=16))
    assert calls["count"] >= 16


def test_pin_uses_secrets_choice(monkeypatch):
    calls = _spy_on(monkeypatch, "choice")
    generators.generate_pin(8)
    assert calls["count"] == 8


def test_passphrase_uses_secrets_choice(monkeypatch):
    calls = _spy_on(monkeypatch, "choice")
    generators.generate_passphrase(6)
    assert calls["count"] == 6


def test_hex_token_uses_secrets_token_hex(monkeypatch):
    received = {}
    real = generators.secrets.token_hex

    def spy(nbytes):
        received["nbytes"] = nbytes
        return real(nbytes)

    monkeypatch.setattr(generators.secrets, "token_hex", spy)
    generators.generate_hex_token(32)
    assert received["nbytes"] == 32


def test_urlsafe_token_uses_secrets_token_urlsafe(monkeypatch):
    received = {}
    real = generators.secrets.token_urlsafe

    def spy(nbytes):
        received["nbytes"] = nbytes
        return real(nbytes)

    monkeypatch.setattr(generators.secrets, "token_urlsafe", spy)
    generators.generate_urlsafe_token(32)
    assert received["nbytes"] == 32


def test_shuffle_uses_secrets_randbelow(monkeypatch):
    calls = _spy_on(monkeypatch, "randbelow")
    generators.generate_password(generators.PasswordPolicy(length=32))
    assert calls["count"] >= 1


def test_repeated_generation_varies():
    # Not a guarantee that any two outputs differ; we only require that the
    # generator is not returning a constant (which would indicate the CSPRNG
    # is not actually being consulted).
    samples = {
        generators.generate_password(generators.PasswordPolicy(length=64)) for _ in range(50)
    }
    assert len(samples) > 1
