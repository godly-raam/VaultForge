"""Tests for the vault cryptographic primitives.

The two known-answer vectors pin the implementation to the standards:

* RFC 9106 (Argon2id) section 5.3
* RFC 8439 (ChaCha20-Poly1305) section 2.8.2

The negative tests assert that invalid parameters raise typed errors *before*
any expensive work, and that no error message carries the material it was given.
"""

import pytest

from vaultforge.vault import crypto
from vaultforge.vault.errors import AuthError, CryptoParameterError

# --- RFC 8439 section 2.8.2 -------------------------------------------------

RFC8439_KEY = bytes(range(0x80, 0xA0))
RFC8439_NONCE = bytes.fromhex("070000004041424344454647")
RFC8439_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
RFC8439_PLAINTEXT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
    b"for the future, sunscreen would be it."
)
RFC8439_CIPHERTEXT = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b6116"
    "1ae10b594f09e26a7e902ecbd0600691"
)

# --- RFC 9106 section 5.3 ---------------------------------------------------


def test_chacha20poly1305_matches_rfc8439_vector():
    produced = crypto.chacha20poly1305_encrypt(
        RFC8439_KEY, RFC8439_NONCE, RFC8439_PLAINTEXT, RFC8439_AAD
    )
    assert produced == RFC8439_CIPHERTEXT


def test_chacha20poly1305_decrypts_rfc8439_vector():
    recovered = crypto.chacha20poly1305_decrypt(
        RFC8439_KEY, RFC8439_NONCE, RFC8439_CIPHERTEXT, RFC8439_AAD
    )
    assert recovered == RFC8439_PLAINTEXT


def test_argon2id_matches_rfc9106_vector():
    derived = crypto.argon2id_derive(
        b"\x01" * 32,
        salt=b"\x02" * 16,
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=32,
        ad=b"\x04" * 12,
        secret=b"\x03" * 8,
    )
    assert derived.hex() == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"


def test_argon2id_ad_and_secret_each_change_the_output():
    base = dict(salt=b"\x02" * 16, length=32, iterations=2, lanes=1, memory_cost=32)
    baseline = crypto.argon2id_derive(b"\x01" * 32, **base)
    assert crypto.argon2id_derive(b"\x01" * 32, ad=b"\x09" * 12, **base) != baseline
    assert crypto.argon2id_derive(b"\x01" * 32, secret=b"\x09" * 8, **base) != baseline


def test_chacha20poly1305_round_trip_random_message():
    key = crypto.generate_dek()
    nonce = crypto.generate_nonce()
    aad = b"some associated data"
    message = b"the quick brown fox\x00\x01\x02"
    assert (
        crypto.chacha20poly1305_decrypt(
            key, nonce, crypto.chacha20poly1305_encrypt(key, nonce, message, aad), aad
        )
        == message
    )


# --- key derivation ---------------------------------------------------------


def test_derive_kek_is_deterministic_and_uses_the_v1_profile():
    password = b"correct horse battery staple"
    salt = crypto.generate_salt()

    first = crypto.derive_kek(password, salt)
    assert len(first) == crypto.KEK_LEN
    # Same inputs -> same key (what lets a vault be reopened).
    assert crypto.derive_kek(password, salt) == first

    # And it is exactly the pinned v1 profile.
    explicit = crypto.argon2id_derive(
        password,
        salt=salt,
        length=crypto.KEK_LEN,
        iterations=3,
        lanes=1,
        memory_cost=65536,
    )
    assert first == explicit


def test_derive_kek_differs_with_a_different_salt():
    password = b"correct horse battery staple"
    assert crypto.derive_kek(password, b"\x00" * 16) != crypto.derive_kek(password, b"\x01" * 16)


# --- AEAD failure modes -----------------------------------------------------


@pytest.mark.parametrize("field", ["key", "nonce", "aad"])
def test_decrypt_rejects_tampered_inputs(field):
    key = crypto.generate_dek()
    nonce = crypto.generate_nonce()
    aad = b"aad"
    ciphertext = crypto.chacha20poly1305_encrypt(key, nonce, b"secret payload", aad)

    if field == "key":
        key2, nonce2, aad2 = bytes([key[0] ^ 0x01]) + key[1:], nonce, aad
    elif field == "nonce":
        key2, nonce2, aad2 = key, bytes([nonce[0] ^ 0x01]) + nonce[1:], aad
    else:
        key2, nonce2, aad2 = key, nonce, b"different aad"

    with pytest.raises(AuthError):
        crypto.chacha20poly1305_decrypt(key2, nonce2, ciphertext, aad2)


def test_decrypt_rejects_a_flipped_ciphertext_bit():
    key = crypto.generate_dek()
    nonce = crypto.generate_nonce()
    ciphertext = crypto.chacha20poly1305_encrypt(key, nonce, b"secret payload", b"")
    flipped = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
    with pytest.raises(AuthError):
        crypto.chacha20poly1305_decrypt(key, nonce, flipped, b"")


def test_auth_error_message_is_unified_and_leaks_nothing():
    key = crypto.generate_dek()
    nonce = crypto.generate_nonce()
    message = b"top secret plaintext"
    ciphertext = crypto.chacha20poly1305_encrypt(key, nonce, message, b"")
    flipped = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
    with pytest.raises(AuthError) as excinfo:
        crypto.chacha20poly1305_decrypt(key, nonce, flipped, b"")
    text = str(excinfo.value)
    assert "wrong master password" in text
    assert message.decode() not in text


# --- parameter validation (must precede expensive work) ----------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"memory_kib": 4, "iterations": 3, "lanes": 1},  # below minimum memory
        {"memory_kib": 8, "iterations": 3, "lanes": 4},  # memory < 8 * lanes
        {"memory_kib": 2_000_000, "iterations": 3, "lanes": 1},  # above maximum
        {"memory_kib": 65536, "iterations": 0, "lanes": 1},  # iterations too low
        {"memory_kib": 65536, "iterations": 11, "lanes": 1},  # iterations too high
        {"memory_kib": 65536, "iterations": 3, "lanes": 0},  # lanes too low
        {"memory_kib": 65536, "iterations": 3, "lanes": 5},  # lanes too high
    ],
)
def test_validate_argon2_params_rejects_out_of_range_values(kwargs):
    with pytest.raises(CryptoParameterError):
        crypto.validate_argon2_params(**kwargs)


def test_validate_argon2_params_rejects_booleans():
    with pytest.raises(CryptoParameterError):
        crypto.validate_argon2_params(memory_kib=65536, iterations=3, lanes=True)


def test_argon2id_derive_rejects_short_salt():
    with pytest.raises(CryptoParameterError):
        crypto.argon2id_derive(b"password", salt=b"short", memory_cost=32)


def test_argon2id_derive_rejects_zero_length():
    with pytest.raises(CryptoParameterError):
        crypto.argon2id_derive(b"password", salt=b"\x00" * 16, length=0, memory_cost=32)


def test_argon2id_derive_rejects_non_bytes_password():
    with pytest.raises(CryptoParameterError):
        crypto.argon2id_derive("password", salt=b"\x00" * 16)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("function", "args"),
    [
        (crypto.chacha20poly1305_encrypt, (b"\x00" * 31, b"\x00" * 12, b"x", b"")),
        (crypto.chacha20poly1305_encrypt, (b"\x00" * 32, b"\x00" * 11, b"x", b"")),
        (crypto.chacha20poly1305_decrypt, (b"\x00" * 32, b"\x00" * 12, b"short", b"")),
    ],
)
def test_aead_rejects_mis_sized_arguments(function, args):
    with pytest.raises(CryptoParameterError):
        function(*args)


def test_wrap_and_unwrap_dek_round_trip_and_validate_lengths():
    kek = b"\x07" * crypto.KEK_LEN
    wrap_nonce = crypto.generate_nonce()
    dek = crypto.generate_dek()
    aad = b"aad"
    wrapped = crypto.wrap_dek(kek, wrap_nonce, dek, aad=aad)
    assert len(wrapped) == crypto.DEK_LEN + crypto.TAG_LEN
    assert crypto.unwrap_dek(kek, wrap_nonce, wrapped, aad=aad) == dek

    with pytest.raises(CryptoParameterError):
        crypto.wrap_dek(kek, wrap_nonce, b"\x00" * 16, aad=aad)
    with pytest.raises(CryptoParameterError):
        crypto.unwrap_dek(kek, wrap_nonce, b"\x00" * 16, aad=aad)


def test_parameter_errors_do_not_echo_the_password():
    material = "hunter2-do-not-print"
    with pytest.raises(CryptoParameterError) as excinfo:
        crypto.argon2id_derive(material.encode(), salt=b"short", memory_cost=32)
    assert material not in str(excinfo.value)


# --- randomness helpers -----------------------------------------------------


def test_random_helpers_return_the_right_sizes_and_do_not_repeat():
    assert len(crypto.generate_salt()) == crypto.SALT_LEN
    assert len(crypto.generate_dek()) == crypto.DEK_LEN
    assert len(crypto.generate_nonce()) == crypto.NONCE_LEN
    assert crypto.generate_dek() != crypto.generate_dek()


def test_wipe_zeroes_a_bytearray():
    buffer = bytearray(b"\x01\x02\x03\x04")
    crypto.wipe(buffer)
    assert buffer == bytearray(4)


def test_crypto_module_uses_secrets_and_never_random():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(crypto))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    assert "secrets" in imported
    assert "random" not in imported
    assert not hasattr(crypto, "random")
