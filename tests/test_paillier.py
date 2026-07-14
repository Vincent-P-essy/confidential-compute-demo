from __future__ import annotations

import random

import pytest

from confidential_compute_demo.paillier import generate_keypair


def test_keygen_is_deterministic() -> None:
    a_pub, _ = generate_keypair(bits=256, seed=42)
    b_pub, _ = generate_keypair(bits=256, seed=42)
    assert a_pub.n == b_pub.n


def test_encrypt_decrypt_roundtrip() -> None:
    public, private = generate_keypair(bits=256, seed=1)
    rng = random.Random(0)
    for value in (0, 1, 42, 999_999):
        assert private.decrypt(public.encrypt(value, rng)) == value


def test_homomorphic_addition() -> None:
    public, private = generate_keypair(bits=256, seed=2)
    rng = random.Random(0)
    c1 = public.encrypt(1000, rng)
    c2 = public.encrypt(2500, rng)
    assert private.decrypt(public.add(c1, c2)) == 3500
    assert private.decrypt(public.add_plain(c1, 5)) == 1005
    assert private.decrypt(public.multiply_plain(c1, 3)) == 3000


def test_encrypt_rejects_out_of_range() -> None:
    public, _ = generate_keypair(bits=256, seed=3)
    rng = random.Random(0)
    with pytest.raises(ValueError, match="range"):
        public.encrypt(-1, rng)
    with pytest.raises(ValueError, match="range"):
        public.encrypt(public.n, rng)


def test_ciphertext_hides_plaintext() -> None:
    public, _ = generate_keypair(bits=256, seed=4)
    rng = random.Random(0)
    assert public.encrypt(7, rng) != 7
    # Fresh randomness makes repeated encryptions differ (semantic security).
    assert public.encrypt(7, rng) != public.encrypt(7, rng)
