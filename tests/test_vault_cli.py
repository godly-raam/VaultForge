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


def test_vault_init_invalid_parent_path_does_not_create_a_vault(tmp_path):
    parent = tmp_path / "not-a-directory"
    parent.write_text("not a directory", encoding="utf-8")
    path = parent / "vault.vf"

    result = _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD])

    assert result.exit_code == 2
    assert "error:" in _stderr(result)
    assert not path.exists()
    assert parent.read_text(encoding="utf-8") == "not a directory"


def test_vault_commands_never_echo_the_password(tmp_path):
    path = tmp_path / "vault.vf"
    init = _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD])
    unlock = _invoke(["vault", "unlock", "--vault", str(path)], [PASSWORD])
    for result in (init, unlock):
        assert PASSWORD not in result.stdout
        assert PASSWORD not in _stderr(result)


def test_vault_init_uses_the_default_path_when_environment_is_unset(tmp_path, monkeypatch):
    default = tmp_path / "default" / "vault.vf"
    monkeypatch.delenv("VAULTFORGE_VAULT", raising=False)
    monkeypatch.setattr(cli.vault_service, "default_vault_path", lambda: default)
    result = _invoke(["vault", "init"], [PASSWORD, PASSWORD])
    assert result.exit_code == 0, _stderr(result)
    assert default.exists()


def test_explicit_vault_option_takes_precedence_over_environment(tmp_path):
    environment_path = tmp_path / "environment.vf"
    explicit_path = tmp_path / "explicit.vf"
    result = runner.invoke(
        app,
        ["vault", "init", "--vault", str(explicit_path)],
        input=f"{PASSWORD}\n{PASSWORD}\n",
        env={"VAULTFORGE_VAULT": str(environment_path)},
    )

    assert result.exit_code == 0, _stderr(result)
    assert explicit_path.exists()
    assert not environment_path.exists()


def test_vault_commands_use_environment_vault_path(tmp_path):
    path = tmp_path / "environment.vf"
    backup = tmp_path / "backup.vf"
    environment = {"VAULTFORGE_VAULT": str(path)}

    initialized = runner.invoke(
        app, ["vault", "init"], input=f"{PASSWORD}\n{PASSWORD}\n", env=environment
    )
    assert initialized.exit_code == 0, _stderr(initialized)
    assert path.exists()

    added = runner.invoke(
        app,
        ["vault", "add", "--type", "note", "--title", "Environment"],
        input=f"private note\n{PASSWORD}\n",
        env=environment,
    )
    assert added.exit_code == 0, _stderr(added)
    entry_id = _stderr(added).split("added entry ", 1)[1].strip()

    listed = runner.invoke(app, ["vault", "list", "--json"], input=f"{PASSWORD}\n", env=environment)
    assert listed.exit_code == 0, _stderr(listed)
    assert json.loads(listed.stdout)[0]["id"] == entry_id

    retrieved = runner.invoke(
        app, ["vault", "get", entry_id], input=f"{PASSWORD}\n", env=environment
    )
    assert retrieved.exit_code == 0, _stderr(retrieved)
    assert 'body: "********"' in retrieved.stdout

    updated = runner.invoke(
        app,
        ["vault", "update", entry_id, "--field", "body"],
        input=f"updated note\n{PASSWORD}\n",
        env=environment,
    )
    assert updated.exit_code == 0, _stderr(updated)

    backed_up = runner.invoke(
        app,
        ["vault", "backup", "--out", str(backup)],
        input=f"{PASSWORD}\n",
        env=environment,
    )
    assert backed_up.exit_code == 0, _stderr(backed_up)
    assert backup.exists()

    unlocked = runner.invoke(app, ["vault", "unlock"], input=f"{PASSWORD}\n", env=environment)
    assert unlocked.exit_code == 0, _stderr(unlocked)

    deleted = runner.invoke(
        app, ["vault", "delete", entry_id], input=f"y\n{PASSWORD}\n", env=environment
    )
    assert deleted.exit_code == 0, _stderr(deleted)


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

    listed = _invoke(["vault", "list", "--json", "--vault", str(path)], [PASSWORD])
    assert listed.exit_code == 0, _stderr(listed)
    metadata = json.loads(listed.stdout)
    assert metadata[0]["id"] == entry_id
    assert metadata[0]["title"] == "Work"
    assert "private-password" not in listed.stdout

    masked = _invoke(["vault", "get", entry_id, "--vault", str(path)], [PASSWORD])
    assert masked.exit_code == 0, _stderr(masked)
    assert "Metadata:" in masked.stdout
    assert "Fields:" in masked.stdout
    assert f'id: "{entry_id}"' in masked.stdout
    assert 'title: "Work"' in masked.stdout
    assert 'type: "login"' in masked.stdout
    assert 'password: "********"' in masked.stdout
    assert 'username: "alice"' in masked.stdout
    assert "private-password" not in masked.stdout

    revealed = _invoke(["vault", "get", entry_id, "--reveal", "--vault", str(path)], [PASSWORD])
    assert revealed.exit_code == 0, _stderr(revealed)
    assert 'password: "private-password"' in revealed.stdout

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
    assert 'title: "Personal"' in persisted.stdout
    assert f'id: "{entry_id}"' in persisted.stdout
    assert 'username: "alice"' in persisted.stdout
    assert 'url: "https://example.test"' in persisted.stdout
    assert 'password: "rotated-secret"' in persisted.stdout

    declined = runner.invoke(app, ["vault", "delete", entry_id, "--vault", str(path)], input="n\n")
    assert declined.exit_code == 0
    assert json.loads(_invoke(["vault", "list", "--json", "--vault", str(path)], [PASSWORD]).stdout)

    deleted = runner.invoke(
        app, ["vault", "delete", entry_id, "--vault", str(path)], input=f"y\n{PASSWORD}\n"
    )
    assert deleted.exit_code == 0, _stderr(deleted)
    assert (
        json.loads(_invoke(["vault", "list", "--json", "--vault", str(path)], [PASSWORD]).stdout)
        == []
    )


def test_vault_list_displays_non_sensitive_table_by_default(tmp_path):
    path = tmp_path / "vault.vf"
    assert _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD]).exit_code == 0
    added = _invoke(
        ["vault", "add", "--type", "login", "--title", "Work", "--vault", str(path)],
        ["alice", "private-password", "https://example.test", "", PASSWORD],
    )
    assert added.exit_code == 0, _stderr(added)
    entry_id = _stderr(added).split("added entry ", 1)[1].strip()

    listed = _invoke(["vault", "list", "--vault", str(path)], [PASSWORD])

    assert listed.exit_code == 0, _stderr(listed)
    assert "Title" in listed.stdout
    assert "Type" in listed.stdout
    assert "ID" in listed.stdout
    assert "Work" in listed.stdout
    assert "login" in listed.stdout
    assert entry_id in listed.stdout
    assert "private-password" not in listed.stdout + _stderr(listed)
    assert "alice" not in listed.stdout


def test_vault_list_json_preserves_metadata_shape(tmp_path):
    path = tmp_path / "vault.vf"
    assert _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD]).exit_code == 0
    added = _invoke(
        ["vault", "add", "--type", "note", "--title", "Memo", "--vault", str(path)],
        ["private body", PASSWORD],
    )
    assert added.exit_code == 0, _stderr(added)

    listed = _invoke(["vault", "list", "--json", "--vault", str(path)], [PASSWORD])

    assert listed.exit_code == 0, _stderr(listed)
    metadata = json.loads(listed.stdout)
    assert set(metadata[0]) == {"id", "type", "title", "tags", "created_at", "updated_at"}
    assert metadata[0]["title"] == "Memo"
    assert "private body" not in listed.stdout + _stderr(listed)


def test_vault_list_reports_an_empty_vault_without_a_table(tmp_path):
    path = tmp_path / "vault.vf"
    assert _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD]).exit_code == 0

    listed = _invoke(["vault", "list", "--vault", str(path)], [PASSWORD])
    as_json = _invoke(["vault", "list", "--json", "--vault", str(path)], [PASSWORD])

    assert listed.exit_code == 0, _stderr(listed)
    assert listed.stdout.endswith("No entries found.\n")
    assert as_json.exit_code == 0, _stderr(as_json)
    assert json.loads(as_json.stdout) == []


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


def test_vault_commands_reject_malformed_ids_before_prompting(tmp_path):
    path = tmp_path / "vault.vf"
    assert _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD]).exit_code == 0
    original = path.read_bytes()
    malformed_id = "not-an-entry-id"

    commands = (
        ["vault", "get", malformed_id, "--vault", str(path)],
        ["vault", "update", malformed_id, "--title", "Changed", "--vault", str(path)],
        ["vault", "delete", malformed_id, "--vault", str(path)],
    )
    for command in commands:
        result = runner.invoke(app, command, input="never-echo-this\n")
        output = result.stdout + _stderr(result)
        assert result.exit_code == 2
        assert "entry ID must be 32 lowercase hexadecimal characters" in output
        assert "never-echo-this" not in output
        assert "Traceback" not in output
        assert path.read_bytes() == original


def test_vault_cli_rejects_invalid_entry_type_and_missing_required_options(tmp_path):
    path = tmp_path / "vault.vf"
    invalid_type = runner.invoke(
        app, ["vault", "add", "--type", "unknown", "--title", "New", "--vault", str(path)]
    )
    missing_options = runner.invoke(app, ["vault", "add", "--vault", str(path)])

    for result in (invalid_type, missing_options):
        output = result.stdout + _stderr(result)
        assert result.exit_code == 2
        assert "Traceback" not in output
    assert not path.exists()


def test_vault_cli_invalid_field_does_not_echo_prompted_value(tmp_path):
    path = tmp_path / "vault.vf"
    _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD])
    added = runner.invoke(
        app,
        ["vault", "add", "--type", "note", "--title", "Memo", "--vault", str(path)],
        input=f"private body\n{PASSWORD}\n",
    )
    entry_id = _stderr(added).split("added entry ", 1)[1].strip()
    original = path.read_bytes()

    invalid = runner.invoke(
        app,
        ["vault", "update", entry_id, "--field", "unknown", "--vault", str(path)],
        input=f"never-echo-this\n{PASSWORD}\n",
    )

    assert invalid.exit_code == 2
    assert "unsupported entry field" in invalid.stdout + _stderr(invalid)
    assert "never-echo-this" not in invalid.stdout + _stderr(invalid)
    assert "Traceback" not in invalid.stdout + _stderr(invalid)
    assert path.read_bytes() == original


def test_vault_add_invalid_totp_value_does_not_persist_or_echo_secrets(tmp_path):
    path = tmp_path / "vault.vf"
    assert _invoke(["vault", "init", "--vault", str(path)], [PASSWORD, PASSWORD]).exit_code == 0
    original = path.read_bytes()

    invalid = _invoke(
        ["vault", "add", "--type", "totp", "--title", "Authenticator", "--vault", str(path)],
        ["totp-secret", "9", "30", "sha1", "", "", PASSWORD],
    )

    assert invalid.exit_code == 2
    assert "digits must be 6, 7, or 8" in _stderr(invalid)
    assert "totp-secret" not in invalid.stdout + _stderr(invalid)
    assert "Traceback" not in invalid.stdout + _stderr(invalid)
    assert path.read_bytes() == original


def test_vault_backup_and_restore_create_encrypted_new_files(tmp_path):
    source = tmp_path / "vault.vf"
    backup = tmp_path / "backup.vf"
    restored = tmp_path / "restored.vf"
    assert _invoke(["vault", "init", "--vault", str(source)], [PASSWORD, PASSWORD]).exit_code == 0

    backed_up = _invoke(
        ["vault", "backup", "--vault", str(source), "--out", str(backup)], [PASSWORD]
    )
    assert backed_up.exit_code == 0, _stderr(backed_up)
    assert backup.read_bytes() == source.read_bytes()
    assert "forgotten master password" in _stderr(backed_up)

    restored_result = _invoke(
        ["vault", "restore", "--backup", str(backup), "--out", str(restored)], [PASSWORD]
    )
    assert restored_result.exit_code == 0, _stderr(restored_result)
    assert restored.read_bytes() == backup.read_bytes()


def test_vault_backup_errors_do_not_echo_password_or_overwrite(tmp_path):
    source = tmp_path / "vault.vf"
    backup = tmp_path / "backup.vf"
    assert _invoke(["vault", "init", "--vault", str(source)], [PASSWORD, PASSWORD]).exit_code == 0
    backup.write_bytes(b"existing")

    existing = _invoke(
        ["vault", "backup", "--vault", str(source), "--out", str(backup)], [PASSWORD]
    )
    wrong = _invoke(
        ["vault", "backup", "--vault", str(source), "--out", str(tmp_path / "new.vf")],
        ["wrong-password"],
    )

    assert existing.exit_code == 2
    assert backup.read_bytes() == b"existing"
    assert wrong.exit_code == 1
    assert "wrong-password" not in wrong.stdout + _stderr(wrong)


def test_vault_group_help_lists_crud_and_backup_commands():
    result = runner.invoke(app, ["vault", "--help"])
    assert result.exit_code == 0
    commands = ("init", "unlock", "add", "list", "get", "update", "delete", "backup", "restore")
    for command in commands:
        assert command in result.stdout
