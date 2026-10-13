"""End-to-end tests for the ``vaultforge vault`` commands."""

import json

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


def test_vault_cli_crud_persists_and_masks_sensitive_fields(tmp_path):
    path = tmp_path / "vault.vf"
    initialized = _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD])
    assert initialized.exit_code == 0

    added = _invoke(
        ["vault", "add", "--type", "login", "--title", "Work", "--vault", str(path)],
        ["alice", "private-password", "https://example.test", "", PASSWORD],
    )
    assert added.exit_code == 0, _stderr(added)
    assert "private-password" not in added.stdout + _stderr(added)
    entry_id = _stderr(added).split("added entry ", 1)[1].strip()
    assert len(entry_id) == 32

    listed = _invoke(["vault", "list", "--vault", str(path)], [PASSWORD])
    assert listed.exit_code == 0, _stderr(listed)
    metadata = json.loads(listed.stdout)
    assert metadata[0]["id"] == entry_id
    assert metadata[0]["title"] == "Work"
    assert "private-password" not in listed.stdout

    masked = _invoke(["vault", "get", entry_id, "--vault", str(path)], [PASSWORD])
    assert masked.exit_code == 0, _stderr(masked)
    assert json.loads(masked.stdout)["fields"]["password"] == "********"
    assert "private-password" not in masked.stdout

    revealed = _invoke(["vault", "get", entry_id, "--reveal", "--vault", str(path)], [PASSWORD])
    assert revealed.exit_code == 0, _stderr(revealed)
    assert json.loads(revealed.stdout)["fields"]["password"] == "private-password"

    updated = _invoke(
        [
            "vault",
            "update",
            entry_id,
            "--title",
            "Personal",
            "--field",
            "password",
            "--vault",
            str(path),
        ],
        ["rotated-secret", PASSWORD],
    )
    assert updated.exit_code == 0, _stderr(updated)
    assert "rotated-secret" not in updated.stdout + _stderr(updated)
    persisted = _invoke(["vault", "get", entry_id, "--reveal", "--vault", str(path)], [PASSWORD])
    assert json.loads(persisted.stdout)["title"] == "Personal"
    assert json.loads(persisted.stdout)["id"] == entry_id
    assert json.loads(persisted.stdout)["fields"]["username"] == "alice"
    assert json.loads(persisted.stdout)["fields"]["url"] == "https://example.test"
    assert json.loads(persisted.stdout)["fields"]["password"] == "rotated-secret"

    declined = runner.invoke(app, ["vault", "delete", entry_id, "--vault", str(path)], input="n\n")
    assert declined.exit_code == 0
    assert json.loads(_invoke(["vault", "list", "--vault", str(path)], [PASSWORD]).stdout)

    deleted = runner.invoke(
        app, ["vault", "delete", entry_id, "--vault", str(path)], input=f"y\n{PASSWORD}\n"
    )
    assert deleted.exit_code == 0, _stderr(deleted)
    assert json.loads(_invoke(["vault", "list", "--vault", str(path)], [PASSWORD]).stdout) == []


def test_vault_cli_reports_missing_ids_and_wrong_password_safely(tmp_path):
    path = tmp_path / "vault.vf"
    _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD])

    missing = _invoke(["vault", "get", "f" * 32, "--vault", str(path)], [PASSWORD])
    assert missing.exit_code == 2
    assert "entry not found" in _stderr(missing)

    wrong = _invoke(["vault", "list", "--vault", str(path)], ["wrong-password"])
    assert wrong.exit_code == 1
    assert "authentication failed" in _stderr(wrong)
    assert "wrong-password" not in wrong.stdout + _stderr(wrong)


def test_vault_cli_invalid_field_does_not_echo_prompted_value(tmp_path):
    path = tmp_path / "vault.vf"
    _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD])
    added = runner.invoke(
        app,
        ["vault", "add", "--type", "note", "--title", "Memo", "--vault", str(path)],
        input=f"private body\n{PASSWORD}\n",
    )
    entry_id = _stderr(added).split("added entry ", 1)[1].strip()

    invalid = runner.invoke(
        app,
        ["vault", "update", entry_id, "--field", "unknown", "--vault", str(path)],
        input=f"never-echo-this\n{PASSWORD}\n",
    )

    assert invalid.exit_code == 2
    assert "never-echo-this" not in invalid.stdout + _stderr(invalid)


def test_vault_group_help_lists_crud_commands():
    result = runner.invoke(app, ["vault", "--help"])
    assert result.exit_code == 0
    for command in ("init", "unlock", "add", "list", "get", "update", "delete"):
        assert command in result.stdout
