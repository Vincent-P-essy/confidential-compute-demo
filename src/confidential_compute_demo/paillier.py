"""A from-scratch Paillier additively-homomorphic cryptosystem.

Paillier lets you add ciphertexts without decrypting: ``E(a) * E(b) mod n^2``
decrypts to ``a + b``, and ``E(a)^k`` decrypts to ``k * a``. That is exactly what
is needed to compute an encrypted SUM, COUNT, or AVG over a column no one ever
decrypts row by row.

The implementation is correct textbook Paillier with the standard ``g = n + 1``
optimization. Key generation is driven by an injected, *seeded* PRNG so the demos
are byte-reproducible; that PRNG is not cryptographically secure, so these keys
are for demonstration only, never for protecting real data. Default key sizes are
kept modest so the demos and benchmark run quickly.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from math import gcd

_SMALL_PRIMES = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)


def _is_probable_prime(candidate: int, rng: random.Random, *, rounds: int = 40) -> bool:
    if candidate < 2:
        return False
    for prime in _SMALL_PRIMES:
        if candidate % prime == 0:
            return candidate == prime
    d = candidate - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = rng.randrange(2, candidate - 1)
        x = pow(a, d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int, rng: random.Random) -> int:
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate, rng):
            return candidate


@dataclass(frozen=True)
class PaillierPublicKey:
    n: int

    @property
    def n_sq(self) -> int:
        return self.n * self.n

    def encrypt(self, message: int, rng: random.Random) -> int:
        if not 0 <= message < self.n:
            raise ValueError("message out of plaintext range")
        r = self._unit(rng)
        return ((1 + message * self.n) % self.n_sq) * pow(r, self.n, self.n_sq) % self.n_sq

    def add(self, left: int, right: int) -> int:
        return left * right % self.n_sq

    def add_plain(self, cipher: int, message: int) -> int:
        return cipher * ((1 + message * self.n) % self.n_sq) % self.n_sq

    def multiply_plain(self, cipher: int, scalar: int) -> int:
        return pow(cipher, scalar, self.n_sq)

    def _unit(self, rng: random.Random) -> int:
        while True:
            r = rng.randrange(1, self.n)
            if gcd(r, self.n) == 1:
                return r


@dataclass(frozen=True)
class PaillierPrivateKey:
    public: PaillierPublicKey
    lam: int
    mu: int

    def decrypt(self, cipher: int) -> int:
        u = pow(cipher, self.lam, self.public.n_sq)
        el = (u - 1) // self.public.n
        return el * self.mu % self.public.n


def generate_keypair(
    *, bits: int = 256, seed: int = 20260714
) -> tuple[PaillierPublicKey, PaillierPrivateKey]:
    """Generate a demo Paillier keypair deterministically from ``seed``."""

    rng = random.Random(seed)
    p = _generate_prime(bits, rng)
    q = _generate_prime(bits, rng)
    while q == p:
        q = _generate_prime(bits, rng)
    n = p * q
    lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
    mu = pow(lam, -1, n)
    public = PaillierPublicKey(n=n)
    return public, PaillierPrivateKey(public=public, lam=lam, mu=mu)
