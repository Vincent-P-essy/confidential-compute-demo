"""The catalogue of confidential-computing demonstrations.

Seven demos exercise the four primitives end to end and check each against a
plaintext reference or an expected rejection. Every demo is deterministic, so the
catalogue doubles as a correctness suite: the benchmark fails if any primitive
stops matching its reference.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from functools import lru_cache

from .attestation import AttestationVerifier, Enclave, measure
from .enclave import ConfidentialEnclave, SealError, unseal
from .encrypted_analytics import encrypt_table, query_average, query_sum
from .models import DemoKind, DemoResult
from .mpc import Party, secure_aggregate
from .paillier import PaillierPrivateKey, PaillierPublicKey, generate_keypair

# Synthetic salary dataset: (id, department, salary). Fictional.
EMPLOYEES: tuple[tuple[int, str, int], ...] = (
    (1, "engineering", 95_000),
    (2, "engineering", 120_000),
    (3, "sales", 80_000),
    (4, "sales", 90_000),
    (5, "engineering", 110_000),
)

TRUSTED_CODE = b"aggregation-enclave:v1"
TAMPERED_CODE = b"aggregation-enclave:v1+exfil-backdoor"
NONCE_ONE = b"attestation-challenge-0001"
NONCE_TWO = b"attestation-challenge-0002"


@lru_cache
def _keypair() -> tuple[PaillierPublicKey, PaillierPrivateKey]:
    return generate_keypair(bits=256, seed=20260714)


def demo_homomorphic_sum() -> DemoResult:
    public, private = _keypair()
    rng = random.Random(1)
    table = encrypt_table(list(EMPLOYEES), public, rng)
    decrypted = query_sum(table, private)
    plaintext = sum(salary for _id, _dept, salary in EMPLOYEES)
    sample_cipher = str(table.rows[0].cipher)
    ok = decrypted == plaintext and table.rows[0].cipher != EMPLOYEES[0][2]
    return DemoResult(
        id="homomorphic-encrypted-sum",
        kind=DemoKind.HOMOMORPHIC,
        title="Encrypted SUM without decrypting rows",
        claim="Summing Paillier ciphertexts yields the true total; no row is decrypted.",
        passed=ok,
        detail=f"decrypted total {decrypted} equals plaintext total {plaintext}",
        evidence={
            "plaintext_total": str(plaintext),
            "decrypted_total": str(decrypted),
            "row0_ciphertext_prefix": sample_cipher[:24] + "...",
        },
    )


def demo_homomorphic_filtered_average() -> DemoResult:
    public, private = _keypair()
    rng = random.Random(2)
    table = encrypt_table(list(EMPLOYEES), public, rng)
    encrypted_avg = query_average(table, private, department="engineering")
    eng = [salary for _id, dept, salary in EMPLOYEES if dept == "engineering"]
    plaintext_avg = sum(eng) / len(eng)
    ok = abs(encrypted_avg - plaintext_avg) < 1e-9
    return DemoResult(
        id="homomorphic-filtered-average",
        kind=DemoKind.HOMOMORPHIC,
        title="Encrypted AVG with a plaintext filter",
        claim="AVG(salary) WHERE department='engineering' over encrypted salaries.",
        passed=ok,
        detail=f"encrypted average {encrypted_avg:.2f} equals plaintext {plaintext_avg:.2f}",
        evidence={
            "matched_rows": str(len(eng)),
            "encrypted_average": f"{encrypted_avg:.2f}",
            "plaintext_average": f"{plaintext_avg:.2f}",
        },
    )


def demo_mpc_secure_average() -> DemoResult:
    salaries = [salary for _id, _dept, salary in EMPLOYEES]
    parties = [Party(name=f"p{i}", value=v) for i, v in enumerate(salaries)]
    result = secure_aggregate(parties, seed=7)
    true_total = sum(salaries)
    # Privacy evidence: no share a party received equals a plaintext salary.
    leaked = any(
        share in salaries for shares in result.received_shares.values() for share in shares
    )
    ok = result.total == true_total and not leaked
    return DemoResult(
        id="mpc-secure-average",
        kind=DemoKind.MPC,
        title="Average salary across parties, no value revealed",
        claim="Additive secret sharing yields the total without any party revealing its value.",
        passed=ok,
        detail=f"secure total {result.total} equals true total {true_total}; no salary leaked",
        evidence={
            "secure_total": str(result.total),
            "true_total": str(true_total),
            "secure_average": f"{result.average:.2f}",
            "any_share_leaks_salary": str(leaked),
        },
    )


def demo_attestation_accept() -> DemoResult:
    enclave = Enclave(TRUSTED_CODE)
    verifier = AttestationVerifier(measure(TRUSTED_CODE), enclave.attestation_key)
    quote = enclave.quote(NONCE_ONE, b"result-report")
    outcome = verifier.verify(quote, NONCE_ONE)
    return DemoResult(
        id="attestation-accept",
        kind=DemoKind.ATTESTATION,
        title="A genuine enclave is attested",
        claim="A quote from the expected code with a fresh nonce verifies.",
        passed=outcome.accepted,
        detail=outcome.reason,
        evidence={"measurement": enclave.measurement[:16] + "...", "reason": outcome.reason},
    )


def demo_attestation_reject_tampered() -> DemoResult:
    tampered = Enclave(TAMPERED_CODE)  # same platform key, different code measurement
    verifier = AttestationVerifier(measure(TRUSTED_CODE), tampered.attestation_key)
    quote = tampered.quote(NONCE_ONE, b"result-report")
    outcome = verifier.verify(quote, NONCE_ONE)
    ok = not outcome.accepted and "measurement" in outcome.reason
    return DemoResult(
        id="attestation-reject-tampered",
        kind=DemoKind.ATTESTATION,
        title="Tampered enclave code is rejected",
        claim="A validly signed quote over the wrong measurement is refused.",
        passed=ok,
        detail=outcome.reason,
        evidence={
            "expected_measurement": measure(TRUSTED_CODE)[:16] + "...",
            "actual_measurement": tampered.measurement[:16] + "...",
            "reason": outcome.reason,
        },
    )


def demo_attestation_reject_replay() -> DemoResult:
    enclave = Enclave(TRUSTED_CODE)
    verifier = AttestationVerifier(measure(TRUSTED_CODE), enclave.attestation_key)
    first = verifier.verify(enclave.quote(NONCE_ONE, b"r"), NONCE_ONE)
    # Verifier now issues a fresh challenge; attacker replays the old quote.
    replayed = verifier.verify(enclave.quote(NONCE_ONE, b"r"), NONCE_TWO)
    ok = first.accepted and not replayed.accepted and "nonce" in replayed.reason
    return DemoResult(
        id="attestation-reject-replay",
        kind=DemoKind.ATTESTATION,
        title="A replayed quote is rejected",
        claim="A quote bound to a stale nonce fails the freshness check.",
        passed=ok,
        detail=replayed.reason,
        evidence={"first_accepted": str(first.accepted), "replay_reason": replayed.reason},
    )


def demo_sealed_computation() -> DemoResult:
    enclave = ConfidentialEnclave(TRUSTED_CODE)
    salaries = [salary for _id, _dept, salary in EMPLOYEES]
    sealed = [enclave.seal_input(v, i) for i, v in enumerate(salaries)]

    host_can_read = True
    try:
        unseal(sealed[0], measure(b"host-controlled-code"))
    except SealError:
        host_can_read = False

    reducer: Callable[[list[int]], int] = sum
    result = enclave.compute(sealed, reducer, NONCE_ONE)
    verifier = AttestationVerifier(enclave.measurement, enclave.attestation_key)
    attested = verifier.verify(result.quote, NONCE_ONE)
    ok = result.value == sum(salaries) and not host_can_read and attested.accepted
    return DemoResult(
        id="sealed-computation",
        kind=DemoKind.SEALED,
        title="Compute on sealed inputs the host cannot read",
        claim="Inputs are sealed to the measurement; only the attested result leaves the enclave.",
        passed=ok,
        detail=f"result {result.value} attested; host sees only ciphertext",
        evidence={
            "result": str(result.value),
            "host_can_unseal": str(host_can_read),
            "host_view_prefix": result.host_view[0].hex()[:24] + "...",
            "attested": str(attested.accepted),
        },
    )


DEMOS: tuple[Callable[[], DemoResult], ...] = (
    demo_homomorphic_sum,
    demo_homomorphic_filtered_average,
    demo_mpc_secure_average,
    demo_attestation_accept,
    demo_attestation_reject_tampered,
    demo_attestation_reject_replay,
    demo_sealed_computation,
)


_DEMO_IDS: tuple[str, ...] = (
    "homomorphic-encrypted-sum",
    "homomorphic-filtered-average",
    "mpc-secure-average",
    "attestation-accept",
    "attestation-reject-tampered",
    "attestation-reject-replay",
    "sealed-computation",
)


def run_all() -> list[DemoResult]:
    return [demo() for demo in DEMOS]


def run_one(demo_id: str) -> DemoResult | None:
    for demo in DEMOS:
        result = demo()
        if result.id == demo_id:
            return result
    return None


def ground_truth() -> dict[str, bool]:
    """Every demo is expected to pass: primitives compute correctly and controls reject."""

    return {demo_id: True for demo_id in _DEMO_IDS}
