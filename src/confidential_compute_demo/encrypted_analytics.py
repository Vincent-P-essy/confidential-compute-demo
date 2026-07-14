"""Aggregate queries over an encrypted column using Paillier.

A table keeps non-sensitive attributes in the clear (an id, a department) and one
sensitive column encrypted per row. Aggregate queries — ``COUNT``, ``SUM``,
``AVG``, with an optional filter on a plaintext attribute — are computed by
multiplying the matching ciphertexts, and only the aggregate is decrypted. No
individual sensitive value is ever recovered.

This is what additively-homomorphic encryption enables: encrypted analytics with
additive aggregates. It is deliberately not general-purpose SQL; multiplicative
or comparison predicates on the encrypted column would need fully-homomorphic
encryption (BFV/CKKS), which is out of scope and called out in the limitations.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .paillier import PaillierPrivateKey, PaillierPublicKey


@dataclass(frozen=True)
class EncryptedRow:
    row_id: int
    department: str
    cipher: int


@dataclass(frozen=True)
class EncryptedTable:
    public: PaillierPublicKey
    rows: tuple[EncryptedRow, ...]

    def _match(self, department: str | None) -> tuple[EncryptedRow, ...]:
        if department is None:
            return self.rows
        return tuple(row for row in self.rows if row.department == department)

    def encrypted_sum(self, *, department: str | None = None) -> int:
        matched = self._match(department)
        if not matched:
            return self.public.encrypt(0, random.Random(0))
        total = matched[0].cipher
        for row in matched[1:]:
            total = self.public.add(total, row.cipher)
        return total

    def count(self, *, department: str | None = None) -> int:
        return len(self._match(department))


def encrypt_table(
    records: list[tuple[int, str, int]],
    public: PaillierPublicKey,
    rng: random.Random,
) -> EncryptedTable:
    """Encrypt the sensitive column of ``(id, department, value)`` records."""

    rows = tuple(
        EncryptedRow(row_id=row_id, department=department, cipher=public.encrypt(value, rng))
        for row_id, department, value in records
    )
    return EncryptedTable(public=public, rows=rows)


def query_sum(
    table: EncryptedTable, private: PaillierPrivateKey, *, department: str | None = None
) -> int:
    return private.decrypt(table.encrypted_sum(department=department))


def query_average(
    table: EncryptedTable, private: PaillierPrivateKey, *, department: str | None = None
) -> float:
    count = table.count(department=department)
    if count == 0:
        return 0.0
    return query_sum(table, private, department=department) / count
