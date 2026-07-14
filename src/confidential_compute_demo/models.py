"""Serializable result model for confidential-computing demonstrations."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class DemoKind(StrEnum):
    HOMOMORPHIC = "homomorphic"
    MPC = "mpc"
    ATTESTATION = "attestation"
    SEALED = "sealed"


class Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DemoResult(Frozen):
    """The outcome of one demonstration.

    ``passed`` means the primitive behaved as claimed: a correct computation
    matched its plaintext reference, or a security control correctly rejected a
    bad input. ``evidence`` carries the concrete numbers a reviewer can check.
    """

    id: str
    title: str
    kind: DemoKind
    passed: bool
    claim: str = Field(max_length=300)
    detail: str = Field(max_length=400)
    evidence: dict[str, str] = Field(default_factory=dict)
