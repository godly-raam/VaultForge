"""Tests for canonical payload serialization and strict parsing."""

import json

import pytest

from vaultforge.vault import payload
from vaultforge.vault.errors import CorruptPayloadError, PayloadValidationError

ID_A = "0" * 32
ID_B = "1" * 32
ID_C = "a" * 32
ID_D = "f" * 32


def _entry(entry_id, entry_type, fields, **overrides):
    entry = {
        "id": entry_id,
        "type": entry_type,
        "title": "sample",
        "tags": ["work"],
        "created_at": 1_700_000_000,
        "updated_at": 1_700_000_001,
        "fields": fields,
    }
    entry.update(overrides)
    return entry


def _valid_vault():
    return {
        "schema": 1,
        "entries": [
            _entry(ID_A, "login", {"username": "me", "password": "s3cret", "url": "https://x"}),
            _entry(
                ID_B,
                "totp",
                {"secret": "JBSWY3DPEHPK3PXP", "digits": 6, "period": 30, "algorithm": "sha1"},
            ),
            _entry(ID_C, "recovery", {"codes": ["aaaa-bbbb", "cccc-dddd"]}),
            _entry(ID_D, "note", {"body": "remember to rotate keys"}),
        ],
    }


def _encoded(obj):
    return json.dumps(obj).encode("utf-8")


# --- canonical serialization ------------------------------------------------


def test_serialize_is_canonical_sorted_and_compact():
    assert payload.serialize_payload({"schema": 1, "entries": []}) == b'{"entries":[],"schema":1}'


def test_serialize_escapes_non_ascii():
    vault = {"schema": 1, "entries": [_entry(ID_A, "note", {"body": "caf\u00e9"})]}
    encoded = payload.serialize_payload(vault)
    assert b"caf\\u00e9" in encoded
    assert b"caf\xc3\xa9" not in encoded
    assert payload.deserialize_payload(encoded) == vault


@pytest.mark.parametrize(
    "vault",
    [
        {"schema": 1, "entries": []},
        _valid_vault(),
        {"schema": 1, "entries": [_entry(ID_A, "login", {"username": "", "password": ""})]},
    ],
)
def test_serialize_deserialize_round_trip(vault):
    assert payload.deserialize_payload(payload.serialize_payload(vault)) == vault


# --- strict JSON parsing ----------------------------------------------------


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"not json at all", "not valid JSON"),
        (b"\xff\xfe\xfd", "UTF-8"),
        (b'{"schema":1,"schema":1,"entries":[]}', "duplicate"),
        (b'{"schema":1,"entries":[],"n":1.5}', "floating-point"),
        (b'{"schema":1,"entries":[],"n":NaN}', "non-finite"),
        (b'{"schema":1,"entries":[],"n":Infinity}', "non-finite"),
    ],
)
def test_deserialize_rejects_malformed_or_forbidden_json(data, reason):
    with pytest.raises(CorruptPayloadError) as excinfo:
        payload.deserialize_payload(data)
    assert reason in str(excinfo.value)


def test_deserialize_rejects_non_object_and_non_bytes():
    with pytest.raises(CorruptPayloadError):
        payload.deserialize_payload(b"[]")
    with pytest.raises(CorruptPayloadError):
        payload.deserialize_payload("a string")  # type: ignore[arg-type]


def test_deserialize_rejects_deep_nesting_via_the_depth_cap():
    deep = b'{"schema":1,"entries":[],"deep":' + b"[" * 100 + b"]" * 100 + b"}"
    with pytest.raises(CorruptPayloadError) as excinfo:
        payload.deserialize_payload(deep)
    assert "deep" in str(excinfo.value).lower() or "nest" in str(excinfo.value).lower()


def test_deserialize_rejects_extreme_nesting_without_crashing():
    huge = b"[" * 100_000 + b"]" * 100_000
    with pytest.raises(CorruptPayloadError):
        payload.deserialize_payload(huge)


# --- schema validation (positive) -------------------------------------------


def test_all_entry_types_validate():
    payload.validate_vault(_valid_vault())


@pytest.mark.parametrize("digits", [6, 7, 8])
@pytest.mark.parametrize("algorithm", ["sha1", "sha256", "sha512"])
def test_totp_accepts_supported_digits_and_algorithms(digits, algorithm):
    vault = {
        "schema": 1,
        "entries": [
            _entry(
                ID_B,
                "totp",
                {
                    "secret": "JBSWY3DPEHPK3PXP",
                    "digits": digits,
                    "period": 30,
                    "algorithm": algorithm,
                },
            )
        ],
    }
    payload.validate_vault(vault)


# --- schema validation (negative) -------------------------------------------


@pytest.mark.parametrize(
    "vault",
    [
        {"schema": 1, "entries": [], "extra": 1},  # unknown top-level key
        {"entries": []},  # missing schema
        {"schema": 1},  # missing entries
        {"schema": 2, "entries": []},  # unsupported schema version
        {"schema": 1, "entries": {}},  # entries not a list
    ],
)
def test_top_level_schema_violations(vault):
    with pytest.raises(PayloadValidationError):
        payload.validate_vault(vault)


def test_entries_count_is_capped(monkeypatch):
    monkeypatch.setattr(payload, "MAX_VAULT_ENTRIES", 1)
    vault = {"schema": 1, "entries": [_entry(ID_A, "note", {"body": "x"})] * 2}
    with pytest.raises(PayloadValidationError):
        payload.validate_vault(vault)


@pytest.mark.parametrize(
    "bad_id",
    [
        "0" * 31,  # too short
        "0" * 33,  # too long
        "G" * 32,  # not hex
        "A" * 32,  # uppercase
        "0123456789abcdef0123456789abcde",  # 31 chars
    ],
)
def test_entry_id_must_be_32_lowercase_hex(bad_id):
    vault = {"schema": 1, "entries": [_entry(bad_id, "note", {"body": "x"})]}
    with pytest.raises(PayloadValidationError):
        payload.validate_vault(vault)


def test_entry_unknown_type_is_rejected():
    vault = {"schema": 1, "entries": [_entry(ID_A, "license", {"key": "x"})]}
    with pytest.raises(PayloadValidationError):
        payload.validate_vault(vault)


def test_entry_ids_must_be_unique_within_a_vault():
    entry = _entry(ID_A, "note", {"body": "x"})
    with pytest.raises(PayloadValidationError, match="duplicate entry IDs"):
        payload.validate_vault({"schema": 1, "entries": [entry, dict(entry)]})


def test_entry_rejects_unknown_and_missing_keys():
    extra = _entry(ID_A, "note", {"body": "x"}, surprise=1)
    with pytest.raises(PayloadValidationError):
        payload.validate_vault({"schema": 1, "entries": [extra]})

    missing = _entry(ID_A, "note", {"body": "x"})
    del missing["tags"]
    with pytest.raises(PayloadValidationError):
        payload.validate_vault({"schema": 1, "entries": [missing]})


def test_created_at_must_be_a_real_integer():
    vault = {"schema": 1, "entries": [_entry(ID_A, "note", {"body": "x"}, created_at=1.5)]}
    with pytest.raises(PayloadValidationError):
        payload.validate_vault(vault)

    truthy = {"schema": 1, "entries": [_entry(ID_A, "note", {"body": "x"}, created_at=True)]}
    with pytest.raises(PayloadValidationError):
        payload.validate_vault(truthy)


@pytest.mark.parametrize(
    ("entry_type", "fields"),
    [
        ("login", {"username": "me"}),  # missing password
        ("login", {"username": "me", "password": "x", "rogue": 1}),  # unknown key
        ("totp", {"secret": "", "digits": 6, "period": 30, "algorithm": "sha1"}),  # empty secret
        ("totp", {"secret": "s", "digits": 5, "period": 30, "algorithm": "sha1"}),  # bad digits
        ("totp", {"secret": "s", "digits": 6, "period": 0, "algorithm": "sha1"}),  # period range
        ("totp", {"secret": "s", "digits": 6, "period": 30, "algorithm": "md5"}),  # bad algorithm
        ("recovery", {"codes": "not-a-list"}),  # codes not a list
        ("recovery", {"codes": [1, 2]}),  # code not a string
        ("note", {}),  # missing body
    ],
)
def test_type_specific_field_violations(entry_type, fields):
    vault = {"schema": 1, "entries": [_entry(ID_A, entry_type, fields)]}
    with pytest.raises(PayloadValidationError):
        payload.validate_vault(vault)


def test_string_fields_are_length_capped(monkeypatch):
    monkeypatch.setattr(payload, "MAX_VAULT_FIELD_BYTES", 4)
    vault = {"schema": 1, "entries": [_entry(ID_A, "note", {"body": "way too long"})]}
    with pytest.raises(PayloadValidationError):
        payload.validate_vault(vault)


def test_non_string_object_keys_are_rejected_on_write():
    with pytest.raises(PayloadValidationError):
        payload.validate_vault({1: "one"})


# --- payload size caps ------------------------------------------------------


def test_serialize_enforces_the_payload_size_cap(monkeypatch):
    monkeypatch.setattr(payload, "MAX_VAULT_PAYLOAD_BYTES", 4)
    with pytest.raises(PayloadValidationError):
        payload.serialize_payload({"schema": 1, "entries": []})


def test_deserialize_enforces_the_payload_size_cap(monkeypatch):
    monkeypatch.setattr(payload, "MAX_VAULT_PAYLOAD_BYTES", 4)
    with pytest.raises(CorruptPayloadError):
        payload.deserialize_payload(b'{"schema":1,"entries":[]}')


# --- error hygiene ----------------------------------------------------------


def test_payload_errors_do_not_echo_field_values():
    material = "super-secret-value"
    vault = {
        "schema": 1,
        "entries": [
            _entry(ID_A, "login", {"username": "me", "password": material, "rogue": material})
        ],
    }
    with pytest.raises(PayloadValidationError) as excinfo:
        payload.validate_vault(vault)
    assert material not in str(excinfo.value)
