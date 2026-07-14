from __future__ import annotations

import random

import pytest

from confidential_compute_demo.encrypted_analytics import (
    encrypt_table,
    query_average,
    query_sum,
)
from confidential_compute_demo.mpc import FIELD, Party, secure_aggregate
from confidential_compute_demo.paillier import generate_keypair

RECORDS = [
    (1, "eng", 100),
    (2, "eng", 200),
    (3, "sales", 300),
]


def test_encrypted_sum_and_average() -> None:
    public, private = generate_keypair(bits=256, seed=5)
    table = encrypt_table(RECORDS, public, random.Random(0))
    assert query_sum(table, private) == 600
    assert query_sum(table, private, department="eng") == 300
    assert query_average(table, private, department="eng") == 150.0


def test_average_of_empty_filter_is_zero() -> None:
    public, private = generate_keypair(bits=256, seed=6)
    table = encrypt_table(RECORDS, public, random.Random(0))
    assert query_average(table, private, department="ghost") == 0.0
    assert query_sum(table, private, department="ghost") == 0


def test_mpc_computes_true_total_without_leaking() -> None:
    parties = [Party("a", 100), Party("b", 250), Party("c", 400)]
    result = secure_aggregate(parties, seed=11)
    assert result.total == 750
    assert result.average == 250.0
    # No party's received shares equal a plaintext value.
    plaintext = {100, 250, 400}
    for shares in result.received_shares.values():
        assert not plaintext.intersection(shares)
        assert all(0 <= share < FIELD for share in shares)


def test_mpc_requires_parties() -> None:
    with pytest.raises(ValueError, match="at least one"):
        secure_aggregate([])


def test_mpc_single_party_is_trivially_correct() -> None:
    result = secure_aggregate([Party("solo", 512)], seed=1)
    assert result.total == 512
