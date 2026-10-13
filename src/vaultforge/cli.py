"""Command line interface for VaultForge.

This module is deliberately thin: it parses arguments, builds a policy, calls
into :mod:`vaultforge.generators`, and prints the result to stdout. Generated
secrets are the product of the tool, so they go to stdout and nowhere else --
they are never written to a log, a file, or an error stream.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path

import typer

from . import __version__
from . import otp as otp_lib
from .generators import (
    generate_hex_token,
    generate_passphrase,
    generate_password,
    generate_pin,
    generate_urlsafe_token,
)
from .limits import (
    DEFAULT_OTP_SECRET_BYTES,
    MAX_COUNT,
    MAX_OTP_SECRET_BYTES,
    MAX_PASSPHRASE_WORDS,
    MAX_PASSWORD_LENGTH,
    MAX_PIN_LENGTH,
    MAX_TOKEN_BYTES,
    MIN_OTP_SECRET_BYTES,
)
from .otp import OTPError
from .policy import PasswordPolicy, PolicyError
from .vault import service as vault_service
from .vault import store as vault_store
from .vault.errors import AuthError, VaultError
from .wordlist import WordListError

app = typer.Typer(
    name="vaultforge",
    help="Generate passwords, PINs, tokens, and passphrases, and handle TOTP codes.",
    no_args_is_help=True,
    add_completion=False,
)


class TokenEncoding(str, Enum):
    """Supported token encodings."""

    hex = "hex"
    urlsafe = "urlsafe"


class VaultEntryType(str, Enum):
    """Entry types supported by the frozen vault payload schema."""

    login = "login"
    totp = "totp"
    recovery = "recovery"
    note = "note"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"vaultforge {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """VaultForge command line interface."""


@app.command()
def password(
    length: int = typer.Option(
        16,
        "--length",
        "-l",
        min=1,
        max=MAX_PASSWORD_LENGTH,
        help=f"Total number of characters (1-{MAX_PASSWORD_LENGTH}).",
    ),
    lowercase: bool = typer.Option(
        True, "--lowercase/--no-lowercase", help="Include lowercase letters (a-z)."
    ),
    uppercase: bool = typer.Option(
        True, "--uppercase/--no-uppercase", help="Include uppercase letters (A-Z)."
    ),
    digits: bool = typer.Option(True, "--digits/--no-digits", help="Include digits (0-9)."),
    symbols: bool = typer.Option(
        True, "--symbols/--no-symbols", help="Include punctuation symbols."
    ),
    exclude_ambiguous: bool = typer.Option(
        False,
        "--exclude-ambiguous/--no-exclude-ambiguous",
        help="Exclude easily confused characters (0 O o 1 l I |).",
    ),
    count: int = typer.Option(
        1, "--count", "-n", min=1, max=MAX_COUNT, help="How many passwords to generate."
    ),
) -> None:
    """Generate one or more random passwords."""
    policy = PasswordPolicy(
        length=length,
        lowercase=lowercase,
        uppercase=uppercase,
        digits=digits,
        symbols=symbols,
        exclude_ambiguous=exclude_ambiguous,
    )
    try:
        for _ in range(count):
            typer.echo(generate_password(policy))
    except PolicyError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def pin(
    digits: int = typer.Option(
        6,
        "--digits",
        "-d",
        min=1,
        max=MAX_PIN_LENGTH,
        help=f"Number of digits (1-{MAX_PIN_LENGTH}).",
    ),
    count: int = typer.Option(
        1, "--count", "-n", min=1, max=MAX_COUNT, help="How many PINs to generate."
    ),
) -> None:
    """Generate a numeric PIN, preserving leading zeroes."""
    try:
        for _ in range(count):
            typer.echo(generate_pin(digits))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def token(
    num_bytes: int = typer.Option(
        32,
        "--bytes",
        "-b",
        min=1,
        max=MAX_TOKEN_BYTES,
        help=f"Entropy in bytes (1-{MAX_TOKEN_BYTES}).",
    ),
    encoding: TokenEncoding = typer.Option(
        TokenEncoding.hex, "--encoding", "-e", help="Output encoding: hex or urlsafe."
    ),
    count: int = typer.Option(
        1, "--count", "-n", min=1, max=MAX_COUNT, help="How many tokens to generate."
    ),
) -> None:
    """Generate a cryptographically secure hex or URL-safe token."""
    try:
        for _ in range(count):
            if encoding is TokenEncoding.hex:
                typer.echo(generate_hex_token(num_bytes))
            else:
                typer.echo(generate_urlsafe_token(num_bytes))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def passphrase(
    words: int = typer.Option(
        6,
        "--words",
        "-w",
        min=1,
        max=MAX_PASSPHRASE_WORDS,
        help=f"Number of words (1-{MAX_PASSPHRASE_WORDS}).",
    ),
    separator: str = typer.Option("-", "--separator", "-s", help="String placed between words."),
    capitalize: bool = typer.Option(
        False, "--capitalize/--no-capitalize", help="Capitalise each word."
    ),
    count: int = typer.Option(
        1, "--count", "-n", min=1, max=MAX_COUNT, help="How many passphrases to generate."
    ),
) -> None:
    """Generate a memorable passphrase from the bundled word list."""
    try:
        for _ in range(count):
            typer.echo(generate_passphrase(words, separator=separator, capitalize=capitalize))
    except (ValueError, WordListError) as exc:
        raise typer.BadParameter(str(exc)) from exc


otp_app = typer.Typer(
    help="Generate and verify time-based one-time passwords (TOTP).",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(otp_app, name="otp")


def _read_secret(secret_file: Path | None) -> str:
    """Return a TOTP secret from a file, or prompt for it.

    The value is never accepted as a command-line argument: argv is visible in
    process listings and shell history.
    """
    if secret_file is not None:
        try:
            return secret_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise typer.BadParameter(f"could not read secret file '{secret_file}': {exc}") from exc
    return typer.prompt("TOTP secret", hide_input=True, err=True)


def _read_code(code_file: Path | None) -> str:
    """Return an OTP code from a file, or prompt for it (never via argv)."""
    if code_file is not None:
        try:
            return code_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise typer.BadParameter(f"could not read code file '{code_file}': {exc}") from exc
    return typer.prompt("OTP code", hide_input=True, err=True)


@otp_app.command("secret")
def otp_secret(
    num_bytes: int = typer.Option(
        DEFAULT_OTP_SECRET_BYTES,
        "--bytes",
        "-b",
        help=f"Secret entropy in bytes ({MIN_OTP_SECRET_BYTES}-{MAX_OTP_SECRET_BYTES}).",
    ),
) -> None:
    """Generate a random base32 TOTP secret (enrol it in your authenticator)."""
    try:
        typer.echo(otp_lib.generate_secret(num_bytes))
    except OTPError as exc:
        raise typer.BadParameter(str(exc)) from exc


@otp_app.command("generate")
def otp_generate(
    secret_file: Path | None = typer.Option(
        None,
        "--secret-file",
        help="Read the base32 secret from this file instead of prompting.",
    ),
    digits: int = typer.Option(6, "--digits", "-d", help="Code length: 6, 7, or 8."),
    period: int = typer.Option(30, "--period", "-p", help="Time step in seconds."),
    algorithm: otp_lib.Algorithm = typer.Option(
        otp_lib.Algorithm.sha1, "--algorithm", "-a", help="HMAC hash: sha1, sha256, or sha512."
    ),
    at: float | None = typer.Option(
        None, "--at", help="Generate for a POSIX timestamp instead of the current time."
    ),
    show_remaining: bool = typer.Option(
        False,
        "--show-remaining",
        help="Also print seconds until the code rolls over (to stderr).",
    ),
) -> None:
    """Generate the current TOTP code for a secret."""
    secret = _read_secret(secret_file)
    try:
        if show_remaining:
            remaining = otp_lib.time_remaining(period, for_time=at)
            typer.echo(f"{remaining}s remaining", err=True)
        typer.echo(
            otp_lib.generate_code(
                secret, digits=digits, period=period, algorithm=algorithm, for_time=at
            )
        )
    except OTPError as exc:
        raise typer.BadParameter(str(exc)) from exc


@otp_app.command("verify")
def otp_verify(
    secret_file: Path | None = typer.Option(
        None,
        "--secret-file",
        help="Read the base32 secret from this file instead of prompting.",
    ),
    code_file: Path | None = typer.Option(
        None,
        "--code-file",
        help="Read the code from this file instead of prompting.",
    ),
    digits: int = typer.Option(6, "--digits", "-d", help="Code length: 6, 7, or 8."),
    period: int = typer.Option(30, "--period", "-p", help="Time step in seconds."),
    algorithm: otp_lib.Algorithm = typer.Option(
        otp_lib.Algorithm.sha1, "--algorithm", "-a", help="HMAC hash: sha1, sha256, or sha512."
    ),
    at: float | None = typer.Option(
        None, "--at", help="Verify against a POSIX timestamp instead of the current time."
    ),
    window: int = typer.Option(
        0,
        "--window",
        "-w",
        help="Accept this many time steps of clock skew on each side.",
    ),
) -> None:
    """Verify a TOTP code, exiting 0 when valid and 1 when not."""
    secret = _read_secret(secret_file)
    code = _read_code(code_file)
    try:
        valid = otp_lib.verify_code(
            secret,
            code,
            digits=digits,
            period=period,
            algorithm=algorithm,
            for_time=at,
            valid_window=window,
        )
    except OTPError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo("valid" if valid else "invalid")
    if not valid:
        raise typer.Exit(code=1)


@otp_app.command("uri")
def otp_uri(
    secret_file: Path | None = typer.Option(
        None,
        "--secret-file",
        help="Read the base32 secret from this file instead of prompting.",
    ),
    name: str = typer.Option(..., "--name", "-n", help="Account label, e.g. an email address."),
    issuer: str | None = typer.Option(None, "--issuer", "-i", help="Optional service/issuer name."),
    digits: int = typer.Option(6, "--digits", "-d", help="Code length: 6, 7, or 8."),
    period: int = typer.Option(30, "--period", "-p", help="Time step in seconds."),
    algorithm: otp_lib.Algorithm = typer.Option(
        otp_lib.Algorithm.sha1, "--algorithm", "-a", help="HMAC hash: sha1, sha256, or sha512."
    ),
) -> None:
    """Print an otpauth:// URI for enrolling a secret in an authenticator app."""
    secret = _read_secret(secret_file)
    try:
        typer.echo(
            otp_lib.provisioning_uri(
                secret,
                name=name,
                issuer=issuer,
                digits=digits,
                period=period,
                algorithm=algorithm,
            )
        )
    except OTPError as exc:
        raise typer.BadParameter(str(exc)) from exc


# --- vault ----------------------------------------------------------------

_EXIT_AUTH_FAILURE = 1
_EXIT_ERROR = 2

vault_app = typer.Typer(
    help="Create and open the local encrypted vault.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(vault_app, name="vault")


def _vault_path(vault: Path | None) -> Path:
    return vault if vault is not None else vault_service.default_vault_path()


def _prompt_new_password() -> bytes:
    # default="" lets an empty entry through so we can reject it with a clear
    # message instead of letting click re-prompt until it aborts.
    first = typer.prompt(
        "Master password", hide_input=True, confirmation_prompt=False, default="", err=True
    )
    if not first:
        typer.echo("error: master password must not be empty", err=True)
        raise typer.Exit(code=_EXIT_ERROR)
    second = typer.prompt("Confirm master password", hide_input=True, default="", err=True)
    if first != second:
        typer.echo("error: master passwords do not match", err=True)
        raise typer.Exit(code=_EXIT_ERROR)
    return first.encode("utf-8")


def _prompt_password() -> bytes:
    return typer.prompt("Master password", hide_input=True, default="", err=True).encode("utf-8")


@vault_app.command("init")
def vault_init(
    vault: Path | None = typer.Option(
        None,
        "--vault",
        help="Path to the vault file (default: ~/.vaultforge/vault.vf).",
    ),
) -> None:
    """Create a new encrypted vault with an empty payload."""
    path = _vault_path(vault)
    password = _prompt_new_password()
    try:
        header = vault_service.initialize_vault(path, password)
    except (VaultError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=_EXIT_ERROR) from exc
    typer.echo(f"initialized vault at {path} (id {header.vault_id.hex()})", err=True)
    typer.echo(
        "warning: recovery is disabled; if the master password is lost this vault "
        "cannot be opened. Keep an encrypted backup and the password safe.",
        err=True,
    )


@vault_app.command("add")
def vault_add(
    entry_type: VaultEntryType = typer.Option(..., "--type", help="Entry type."),
    title: str = typer.Option(..., "--title", help="Editable entry title (the ID remains stable)."),
    vault: Path | None = typer.Option(None, "--vault", help="Path to the vault file."),
) -> None:
    """Add and persist an entry; sensitive fields are entered through hidden prompts."""
    fields = _prompt_entry_fields(entry_type)
    password = _prompt_password()
    try:
        entry = vault_service.add_entry(
            _vault_path(vault), password, entry_type=entry_type.value, title=title, fields=fields
        )
    except AuthError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=_EXIT_AUTH_FAILURE) from exc
    except (VaultError, OSError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=_EXIT_ERROR) from exc
    typer.echo(f"added entry {entry['id']}", err=True)


@vault_app.command("list")
def vault_list(
    vault: Path | None = typer.Option(None, "--vault", help="Path to the vault file."),
) -> None:
    """List entry IDs and non-sensitive metadata only."""
    try:
        entries = vault_service.list_entries(_vault_path(vault), _prompt_password())
    except AuthError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=_EXIT_AUTH_FAILURE) from exc
    except (VaultError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=_EXIT_ERROR) from exc
    metadata = [
        {key: entry[key] for key in ("id", "type", "title", "tags", "created_at", "updated_at")}
        for entry in entries
    ]
    typer.echo(json.dumps(metadata, sort_keys=True, separators=(",", ":")))


@vault_app.command("get")
def vault_get(
    entry_id: str,
    reveal: bool = typer.Option(False, "--reveal", help="Display sensitive fields unmasked."),
    vault: Path | None = typer.Option(None, "--vault", help="Path to the vault file."),
) -> None:
    """Retrieve an entry by stable ID; sensitive fields are masked by default."""
    try:
        entry = vault_service.get_entry(_vault_path(vault), _prompt_password(), entry_id)
    except AuthError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=_EXIT_AUTH_FAILURE) from exc
    except (VaultError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=_EXIT_ERROR) from exc
    if not reveal:
        fields = dict(entry["fields"])
        for key in ("password", "secret", "codes", "notes", "body"):
            if key in fields:
                fields[key] = "********"
        entry = {**entry, "fields": fields}
    typer.echo(json.dumps(entry, sort_keys=True, separators=(",", ":")))


@vault_app.command("update")
def vault_update(
    entry_id: str,
    title: str | None = typer.Option(None, "--title", help="Set a new editable title."),
    field: str | None = typer.Option(None, "--field", help="Name of one field to change."),
    vault: Path | None = typer.Option(None, "--vault", help="Path to the vault file."),
) -> None:
    """Update an entry title and/or one prompted field without changing its ID."""
    if title is None and field is None:
        raise typer.BadParameter("provide --title and/or --field")
    field_updates = {field: _prompt_entry_field_value(field)} if field is not None else None
    try:
        vault_service.update_entry(
            _vault_path(vault), _prompt_password(), entry_id, title=title, fields=field_updates
        )
    except AuthError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=_EXIT_AUTH_FAILURE) from exc
    except (VaultError, OSError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=_EXIT_ERROR) from exc
    typer.echo(f"updated entry {entry_id}", err=True)


@vault_app.command("delete")
def vault_delete(
    entry_id: str,
    vault: Path | None = typer.Option(None, "--vault", help="Path to the vault file."),
) -> None:
    """Delete an entry after explicit interactive confirmation."""
    if not typer.confirm(f"Delete entry {entry_id}?", default=False):
        typer.echo("cancelled", err=True)
        return
    try:
        vault_service.delete_entry(_vault_path(vault), _prompt_password(), entry_id)
    except AuthError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=_EXIT_AUTH_FAILURE) from exc
    except (VaultError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=_EXIT_ERROR) from exc
    typer.echo(f"deleted entry {entry_id}", err=True)


def _prompt_entry_fields(entry_type: VaultEntryType) -> dict[str, object]:
    if entry_type is VaultEntryType.login:
        fields: dict[str, object] = {
            "username": typer.prompt("Username"),
            "password": typer.prompt("Password", hide_input=True),
        }
        url = typer.prompt("URL (optional)", default="")
        notes = typer.prompt("Notes (optional)", default="", hide_input=True)
        if url:
            fields["url"] = url
        if notes:
            fields["notes"] = notes
        return fields
    if entry_type is VaultEntryType.totp:
        fields = {
            "secret": typer.prompt("TOTP secret", hide_input=True),
            "digits": typer.prompt("Digits", default=6, type=int),
            "period": typer.prompt("Period", default=30, type=int),
            "algorithm": typer.prompt("Algorithm", default="sha1"),
        }
        issuer = typer.prompt("Issuer (optional)", default="")
        account = typer.prompt("Account (optional)", default="")
        if issuer:
            fields["issuer"] = issuer
        if account:
            fields["account"] = account
        return fields
    if entry_type is VaultEntryType.recovery:
        value = typer.prompt("Recovery codes (comma-separated)", hide_input=True)
        return {"codes": [code.strip() for code in value.split(",") if code.strip()]}
    return {"body": typer.prompt("Note body", hide_input=True)}


def _prompt_entry_field_value(field: str) -> object:
    value = typer.prompt(f"New {field}", hide_input=True)
    if field in {"digits", "period"}:
        try:
            return int(value)
        except ValueError as exc:
            raise typer.BadParameter(f"{field} must be an integer") from exc
    if field == "codes":
        return [code.strip() for code in value.split(",") if code.strip()]
    return value


@vault_app.command("unlock")
def vault_unlock(
    vault: Path | None = typer.Option(
        None,
        "--vault",
        help="Path to the vault file (default: ~/.vaultforge/vault.vf).",
    ),
) -> None:
    """Verify the master password once and exit (no session is kept)."""
    path = _vault_path(vault)
    password = _prompt_password()
    try:
        if vault_store.insecure_permissions(path):
            typer.echo(
                f"warning: {path} is readable by group/other users; "
                f"run 'chmod 600 {path}' to restrict it.",
                err=True,
            )
    except OSError:
        pass
    try:
        vault_service.unlock_vault(path, password)
    except AuthError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=_EXIT_AUTH_FAILURE) from exc
    except (VaultError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=_EXIT_ERROR) from exc
    typer.echo("ok", err=True)


if __name__ == "__main__":
    app()
