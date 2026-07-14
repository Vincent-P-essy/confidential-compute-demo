from __future__ import annotations

import dataclasses

import pytest

from confidential_compute_demo.attestation import (
    AttestationVerifier,
    Enclave,
    measure,
)
from confidential_compute_demo.enclave import ConfidentialEnclave, SealError, seal, unseal

CODE = b"enclave:v1"
NONCE = b"nonce-0001"


def test_genuine_quote_verifies() -> None:
    enclave = Enclave(CODE)
    verifier = AttestationVerifier(measure(CODE), enclave.attestation_key)
    assert verifier.verify(enclave.quote(NONCE, b"data"), NONCE).accepted is True


def test_tampered_measurement_rejected() -> None:
    tampered = Enclave(b"enclave:v1+backdoor")
    verifier = AttestationVerifier(measure(CODE), tampered.attestation_key)
    outcome = verifier.verify(tampered.quote(NONCE, b"data"), NONCE)
    assert outcome.accepted is False
    assert "measurement" in outcome.reason


def test_replayed_nonce_rejected() -> None:
    enclave = Enclave(CODE)
    verifier = AttestationVerifier(measure(CODE), enclave.attestation_key)
    assert verifier.verify(enclave.quote(NONCE, b"d"), NONCE).accepted is True
    outcome = verifier.verify(enclave.quote(NONCE, b"d"), b"fresh-nonce")
    assert outcome.accepted is False
    assert "nonce" in outcome.reason


def test_untrusted_key_rejected() -> None:
    enclave = Enclave(CODE)
    other = Enclave(CODE, platform_seed=999)
    verifier = AttestationVerifier(measure(CODE), other.attestation_key)
    outcome = verifier.verify(enclave.quote(NONCE, b"d"), NONCE)
    assert outcome.accepted is False
    assert "trusted" in outcome.reason


def test_invalid_signature_rejected() -> None:
    enclave = Enclave(CODE)
    verifier = AttestationVerifier(measure(CODE), enclave.attestation_key)
    quote = enclave.quote(NONCE, b"d")
    forged = dataclasses.replace(quote, signature=b"\x00" * 64)
    outcome = verifier.verify(forged, NONCE)
    assert outcome.accepted is False
    assert "signature" in outcome.reason


def test_duplicate_nonce_is_replay() -> None:
    enclave = Enclave(CODE)
    verifier = AttestationVerifier(measure(CODE), enclave.attestation_key)
    verifier.verify(enclave.quote(NONCE, b"d"), NONCE)
    # Same nonce presented again as if fresh: already seen.
    outcome = verifier.verify(enclave.quote(NONCE, b"d"), NONCE)
    assert outcome.accepted is False
    assert "replay" in outcome.reason or "already" in outcome.reason


def test_sealing_roundtrip_and_binding() -> None:
    blob = seal(4242, measure(CODE), 0)
    assert unseal(blob, measure(CODE)) == 4242
    with pytest.raises(SealError):
        unseal(blob, measure(b"different-code"))


def test_confidential_enclave_compute() -> None:
    enclave = ConfidentialEnclave(CODE)
    sealed = [enclave.seal_input(v, i) for i, v in enumerate([10, 20, 30])]
    result = enclave.compute(sealed, sum, NONCE)
    assert result.value == 60
    verifier = AttestationVerifier(enclave.measurement, enclave.attestation_key)
    assert verifier.verify(result.quote, NONCE).accepted is True
    assert all(isinstance(view, bytes) for view in result.host_view)
