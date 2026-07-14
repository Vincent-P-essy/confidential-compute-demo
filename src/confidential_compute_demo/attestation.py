"""Remote attestation with real Ed25519 signatures.

An enclave measures its code (a SHA-256 over the loaded bytes, standing in for an
SGX MRENCLAVE) and produces a *quote*: a signature, under a platform attestation
key, over the measurement, a verifier-supplied nonce, and application report
data. A verifier accepts only if the signature is valid under a trusted key, the
measurement equals the expected value, and the nonce is fresh (not stale, not
replayed).

The cryptography is real: quotes are genuinely signed and verified. What is
simulated is the hardware root of trust — there is no SGX/TDX chip issuing the
attestation key. That boundary is stated in the limitations; everything the
verifier checks is done for real.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class AttestationError(Exception):
    """Raised when a quote cannot be produced."""


def measure(code: bytes) -> str:
    """Return the measurement (hex SHA-256) of enclave code."""

    return hashlib.sha256(code).hexdigest()


@dataclass(frozen=True)
class Quote:
    measurement: str
    nonce: str
    report_data: str
    signature: bytes
    public_key: bytes

    def signed_bytes(self) -> bytes:
        return b"|".join(
            (self.measurement.encode(), self.nonce.encode(), self.report_data.encode())
        )


@dataclass(frozen=True)
class AttestationResult:
    accepted: bool
    reason: str


class Enclave:
    """A measured enclave that can sign attestation quotes."""

    def __init__(self, code: bytes, *, platform_seed: int = 0xA11CE) -> None:
        self.code = code
        self.measurement = measure(code)
        key_seed = hashlib.sha256(f"platform-{platform_seed}".encode()).digest()
        self._key = Ed25519PrivateKey.from_private_bytes(key_seed)

    @property
    def attestation_key(self) -> bytes:
        return self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def quote(self, nonce: bytes, report_data: bytes) -> Quote:
        payload = b"|".join(
            (self.measurement.encode(), nonce.hex().encode(), report_data.hex().encode())
        )
        signature = self._key.sign(payload)
        return Quote(
            measurement=self.measurement,
            nonce=nonce.hex(),
            report_data=report_data.hex(),
            signature=signature,
            public_key=self.attestation_key,
        )


class AttestationVerifier:
    """Checks quotes against an expected measurement and trusted key."""

    def __init__(self, expected_measurement: str, trusted_key: bytes) -> None:
        self.expected_measurement = expected_measurement
        self.trusted_key = trusted_key
        self._seen_nonces: set[str] = set()

    def verify(self, quote: Quote, expected_nonce: bytes) -> AttestationResult:
        if quote.public_key != self.trusted_key:
            return AttestationResult(False, "attestation key is not trusted")
        try:
            Ed25519PublicKey.from_public_bytes(quote.public_key).verify(
                quote.signature, quote.signed_bytes()
            )
        except InvalidSignature:
            return AttestationResult(False, "quote signature is invalid")
        if quote.measurement != self.expected_measurement:
            return AttestationResult(False, "measurement mismatch: untrusted code in the enclave")
        if quote.nonce != expected_nonce.hex():
            return AttestationResult(False, "nonce mismatch: stale or replayed quote")
        if quote.nonce in self._seen_nonces:
            return AttestationResult(False, "nonce already used: replay detected")
        self._seen_nonces.add(quote.nonce)
        return AttestationResult(True, "measurement and freshness verified")
