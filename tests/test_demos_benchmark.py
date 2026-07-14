from __future__ import annotations

import json
from pathlib import Path

from confidential_compute_demo.benchmark import (
    _percentile,
    benchmark,
    committed_ground_truth,
    write_benchmark,
)
from confidential_compute_demo.demos import ground_truth, run_all, run_one
from confidential_compute_demo.reporting import render_markdown, summarize, write_report
from confidential_compute_demo.resources import packaged_path


def test_all_demos_pass() -> None:
    results = run_all()
    assert len(results) == 7
    assert all(r.passed for r in results)


def test_ground_truth_matches_committed_fixture() -> None:
    committed = json.loads(packaged_path("ground-truth.json").read_text(encoding="utf-8"))
    assert committed == ground_truth() == committed_ground_truth()


def test_run_one_known_and_unknown() -> None:
    assert run_one("attestation-accept") is not None
    assert run_one("does-not-exist") is None


def test_percentile() -> None:
    assert _percentile([], 50) == 0.0
    assert _percentile([1.0, 2.0, 3.0], 50) == 2.0


def test_benchmark_is_deterministic() -> None:
    result = benchmark(iterations=3)
    assert result.deterministic is True
    assert result.ground_truth_verified is True
    assert result.matched == result.demos == 7
    assert result.passed == 7
    assert result.report_hash


def test_write_benchmark(tmp_path: Path) -> None:
    path = write_benchmark(tmp_path, benchmark(iterations=2))
    assert json.loads(path.read_text(encoding="utf-8"))["iterations"] == 2


def test_reporting(tmp_path: Path) -> None:
    results = run_all()
    summary = summarize(results)
    assert summary["passed"] == 7
    assert summary["by_kind"]["homomorphic"] == 2
    markdown = render_markdown(results)
    assert "demonstrations passed" in markdown

    paths = write_report(tmp_path, results)
    assert paths["json"].exists()
    assert paths["markdown"].exists()
