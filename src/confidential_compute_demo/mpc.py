"""Secure aggregation via additive secret sharing.

Several parties hold a private number each and want the sum (and average) without
revealing their individual values. Each party splits its value into one random
share per party over a finite field; every party sums the shares it receives; the
partial sums are then combined to reveal only the total. Any single share is
uniformly distributed and independent of the secret, so no party — and no
observer of the shares — learns another party's input.

This is textbook additive secret sharing (secure sum), the building block behind
privacy-preserving analytics. It assumes honest-but-curious parties and does not
add authentication or malicious-security machinery.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

# A large prime field so sums of realistic inputs never wrap.
FIELD = 2**61 - 1


@dataclass(frozen=True)
class Party:
    name: str
    value: int


@dataclass(frozen=True)
class SecureAggregateResult:
    total: int
    count: int
    parties: tuple[str, ...]
    # Shares held by each party after distribution, for inspection/tests.
    received_shares: dict[str, tuple[int, ...]]

    @property
    def average(self) -> float:
        return self.total / self.count if self.count else 0.0


def _split(value: int, parts: int, rng: random.Random) -> list[int]:
    shares = [rng.randrange(FIELD) for _ in range(parts - 1)]
    last = (value - sum(shares)) % FIELD
    shares.append(last)
    return shares


def secure_aggregate(parties: list[Party], *, seed: int = 7) -> SecureAggregateResult:
    """Compute the sum and average of party values without revealing any value."""

    if not parties:
        raise ValueError("at least one party is required")
    rng = random.Random(seed)
    count = len(parties)

    # party_shares[i][j] is the share party i sends to party j.
    party_shares = [_split(party.value % FIELD, count, rng) for party in parties]

    received: dict[str, tuple[int, ...]] = {}
    partials: list[int] = []
    for j, party in enumerate(parties):
        column = tuple(party_shares[i][j] for i in range(count))
        received[party.name] = column
        partials.append(sum(column) % FIELD)

    total = sum(partials) % FIELD
    return SecureAggregateResult(
        total=total,
        count=count,
        parties=tuple(party.name for party in parties),
        received_shares=received,
    )
