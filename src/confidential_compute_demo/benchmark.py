"""Deterministic benchmark over the demonstration catalogue.

Runs every demo ``iterations`` times, checks each result against the committed
ground truth (all demos must pass), confirms the full result set is byte-identical
across passes via a single stable hash, and measures wall time. All primitives are
deterministic here — seeded Paillier keys, seeded secret shares, RFC 8032 Ed25519
signatures, fixed sealing nonces — so the hash never varies.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .demos import ground_truth, run_all
from .models import DemoResult
from .reporting import result_to_dict
from .resources import packaged_path


@dataclass(frozen=True)
class BenchmarkResult:
    iterations: int
    demos: int
    passed: int
    matched: int
    ground_truth_verified: bool
    deterministic: bool
    report_hash: str
    latency_pass_p50_ms: float
    latency_pass_p95_ms: float
    elapsed_seconds: float
    source_revision: str
    source_tree_state: str


def _percentile(samples: list[float], pct: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    rank = max(0, min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1))))
    return round(ordered[rank], 4)


def _outcome_map(results: list[DemoResult]) -> dict[str, object]:
    return {r.id: result_to_dict(r) for r in results}


def _hash(payload: dict[str, object]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def committed_ground_truth() -> dict[str, bool]:
    data: dict[str, bool] = json.loads(
        packaged_path("ground-truth.json").read_text(encoding="utf-8")
    )
    return data


def benchmark(iterations: int = 50) -> BenchmarkResult:
    declared = ground_truth()
    durations_ms: list[float] = []
    hashes: set[str] = set()
    matched = 0
    passed = 0
    started = time.perf_counter()

    for iteration in range(iterations):
        pass_start = time.perf_counter()
        results = run_all()
        durations_ms.append((time.perf_counter() - pass_start) * 1000)
        hashes.add(_hash(_outcome_map(results)))
        if iteration == 0:
            passed = sum(1 for r in results if r.passed)
            matched = sum(1 for r in results if r.passed == declared.get(r.id))

    elapsed = time.perf_counter() - started
    return BenchmarkResult(
        iterations=iterations,
        demos=len(declared),
        passed=passed,
        matched=matched,
        ground_truth_verified=matched == len(declared),
        deterministic=len(hashes) == 1,
        report_hash=next(iter(hashes)) if hashes else "",
        latency_pass_p50_ms=_percentile(durations_ms, 50),
        latency_pass_p95_ms=_percentile(durations_ms, 95),
        elapsed_seconds=round(elapsed, 4),
        source_revision=os.environ.get("CCDEMO_SOURCE_REVISION", "unknown"),
        source_tree_state=os.environ.get("CCDEMO_SOURCE_TREE_STATE", "unknown"),
    )


def write_benchmark(out_dir: Path, result: BenchmarkResult) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "benchmark.json"
    path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
