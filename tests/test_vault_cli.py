"""End-to-end tests for the ``vaultforge vault`` commands."""

from typer.testing import CliRunner

from vaultforge import cli
from vaultforge.cli import app

runner = CliRunner()

PASSWORD = "sup3rs3cr3t-pw"


def _stderr(result):
    return getattr(result, "stderr", "") or ""


def _invoke(args, password_lines):
    return runner.invoke(app, args, input="".join(line + "\n" for line in password_lines))


def test_vault_init_and_unlock_round_trip(tmp_path):
    path = tmp_path / "vault.vf"

    init = _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD])
    assert init.exit_code == 0, _stderr(init)
    assert path.exists()
    assert "initialized" in _stderr(init)
    assert "recovery is disabled" in _stderr(init)

    unlock = _invoke(["vault", "unlock", "--vault", str(path)], [PASSWORD])
    assert unlock.exit_code == 0, _stderr(unlock)
    assert _stderr(unlock).strip().endswith("ok")


def test_vault_init_refuses_an_existing_file(tmp_path):
    path = tmp_path / "vault.vf"
    path.write_bytes(b"original")
    result = _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD])
    assert result.exit_code == 2
    assert "error:" in _stderr(result)
    assert path.read_bytes() == b"original"


def test_vault_init_rejects_a_password_mismatch(tmp_path):
    path = tmp_path / "vault.vf"
    result = _invoke(["vault", "init", "--vault", str(path)], ["one", "two"])
    assert result.exit_code == 2
    assert "do not match" in _stderr(result)
    assert not path.exists()


def test_vault_init_rejects_an_empty_password(tmp_path):
    path = tmp_path / "vault.vf"
    result = runner.invoke(app, ["vault", "init", "--vault", str(path)], input="\n")
    assert result.exit_code == 2
    assert "must not be empty" in _stderr(result)
    assert not path.exists()


def test_vault_unlock_with_the_wrong_password_exits_one(tmp_path):
    path = tmp_path / "vault.vf"
    _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD])

    result = _invoke(["vault", "unlock", "--vault", str(path)], ["not-the-password"])
    assert result.exit_code == 1
    assert "authentication failed" in _stderr(result)


def test_vault_unlock_missing_file_exits_two(tmp_path):
    result = _invoke(["vault", "unlock", "--vault", str(tmp_path / "nope.vf")], [PASSWORD])
    assert result.exit_code == 2
    assert "error:" in _stderr(result)


def test_vault_commands_never_echo_the_password(tmp_path):
    path = tmp_path / "vault.vf"
    init = _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD])
    unlock = _invoke(["vault", "unlock", "--vault", str(path)], [PASSWORD])
    for result in (init, unlock):
        assert PASSWORD not in result.stdout
        assert PASSWORD not in _stderr(result)


def test_vault_init_uses_the_default_path_when_omitted(tmp_path, monkeypatch):
    default = tmp_path / "default" / "vault.vf"
    monkeypatch.setattr(cli.vault_service, "default_vault_path", lambda: default)
    result = _invoke(["vault", "init"], [PASSWORD, PASSWORD])
    assert result.exit_code == 0, _stderr(result)
    assert default.exists()


def test_vault_group_help_lists_both_commands():
    result = runner.invoke(app, ["vault", "--help"])
    assert result.exit_code == 0
    assert "init" in result.stdout
    assert "unlock" in result.stdout
