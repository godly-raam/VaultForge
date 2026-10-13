"""RFC 6238 known-answer vectors for TOTP.

The RFC publishes expected codes for SHA-1, SHA-256, and SHA-512 at fixed
timestamps. Reproducing them exactly is the strongest available evidence that
we emit standard TOTP rather than merely something self-consistent.
"""

import base64

import pytest

from vaultforge.otp import Algorithm, generate_code

# RFC 6238, Appendix B. Seeds are the ASCII digits shown in the RFC; TOTP
# transports them base32-encoded, so we encode them the same way an
# authenticator would.
SECRETS = {
    Algorithm.sha1: base64.b32encode(b"12345678901234567890").decode(),
    Algorithm.sha256: base64.b32encode(b"12345678901234567890123456789012").decode(),
    Algorithm.sha512: base64.b32encode(
        b"1234567890123456789012345678901234567890123456789012345678901234"
    ).decode(),
}

TIMESTAMPS = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]

VECTORS = {
    Algorithm.sha1: ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"],
    Algorithm.sha256: ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"],
    Algorithm.sha512: ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"],
}


@pytest.mark.parametrize("algorithm", list(Algorithm))
def test_rfc6238_vectors(algorithm):
    for timestamp, expected in zip(TIMESTAMPS, VECTORS[algorithm], strict=True):
        code = generate_code(SECRETS[algorithm], digits=8, algorithm=algorithm, for_time=timestamp)
        assert code == expected
