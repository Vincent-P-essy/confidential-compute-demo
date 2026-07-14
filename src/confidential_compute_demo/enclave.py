"""Sealed computation inside a measured enclave.

Inputs are *sealed* to the enclave's measurement with AES-256-GCM using a key
derived from that measurement, so only an enclave running the expected code can
unseal them — the host holds ciphertext only. The enclave unseals inside,
computes, and returns the result together with an attestation quote whose report
data binds the result. The host therefore sees sealed inputs, a result, and a
verifiable quote, but never a plaintext input.

The sealing key derivation and GCM are real. Deterministic nonces are used so the
demos reproduce byte-for-byte; production sealing must use random nonces, which is
noted in the limitations.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .attestation import Enclave, Quote


class SealError(Exception):
    """Raised when a sealed blob cannot be unsealed under a measurement."""


def _sealing_key(measurement: str) -> bytes:
    return hashlib.sha256(f"seal|{measurement}".encode()).digest()


def _nonce(index: int) -> bytes:
    return hashlib.sha256(f"nonce|{index}".encode()).digest()[:12]


@dataclass(frozen=True)
class SealedBlob:
    index: int
    ciphertext: bytes


def seal(value: int, measurement: str, index: int) -> SealedBlob:
    aes = AESGCM(_sealing_key(measurement))
    ciphertext = aes.encrypt(_nonce(index), str(value).encode(), measurement.encode())
    return SealedBlob(index=index, ciphertext=ciphertext)


def unseal(blob: SealedBlob, measurement: str) -> int:
    aes = AESGCM(_sealing_key(measurement))
    try:
        plaintext = aes.decrypt(_nonce(blob.index), blob.ciphertext, measurement.encode())
    except InvalidTag as exc:
        raise SealError("blob is not sealed to this measurement") from exc
    return int(plaintext.decode())


@dataclass(frozen=True)
class ConfidentialResult:
    value: int
    quote: Quote
    host_view: tuple[bytes, ...]  # what the untrusted host could observe


class ConfidentialEnclave:
    """Seals inputs, computes on them internally, and attests the result."""

    def __init__(self, code: bytes, *, platform_seed: int = 0xA11CE) -> None:
        self._enclave = Enclave(code, platform_seed=platform_seed)

    @property
    def measurement(self) -> str:
        return self._enclave.measurement

    @property
    def attestation_key(self) -> bytes:
        return self._enclave.attestation_key

    def seal_input(self, value: int, index: int) -> SealedBlob:
        return seal(value, self.measurement, index)

    def compute(
        self,
        sealed_inputs: list[SealedBlob],
        reducer: Callable[[list[int]], int],
        nonce: bytes,
    ) -> ConfidentialResult:
        """Unseal inputs inside the enclave, reduce them, and attest the result."""

        values = [unseal(blob, self.measurement) for blob in sealed_inputs]
        result = reducer(values)
        report_data = hashlib.sha256(str(result).encode()).digest()
        quote = self._enclave.quote(nonce, report_data)
        host_view = tuple(blob.ciphertext for blob in sealed_inputs)
        return ConfidentialResult(value=result, quote=quote, host_view=host_view)
