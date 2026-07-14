"""Serialize demonstration results into review artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import DemoResult


def result_to_dict(result: DemoResult) -> dict[str, Any]:
    return {
        "id": result.id,
        "title": result.title,
        "kind": result.kind.value,
        "passed": result.passed,
        "claim": result.claim,
        "detail": result.detail,
        "evidence": result.evidence,
    }


def summarize(results: list[DemoResult]) -> dict[str, Any]:
    by_kind: dict[str, int] = {}
    for result in results:
        by_kind[result.kind.value] = by_kind.get(result.kind.value, 0) + 1
    return {
        "demos": len(results),
        "passed": sum(1 for r in results if r.passed),
        "by_kind": by_kind,
        "results": [result_to_dict(r) for r in results],
    }


def render_markdown(results: list[DemoResult]) -> str:
    lines = [
        "# Confidential computing demonstrations",
        "",
        "| Demo | Primitive | Passed | Detail |",
        "|---|---|:---:|---|",
    ]
    for result in results:
        mark = "yes" if result.passed else "**NO**"
        lines.append(f"| {result.id} | {result.kind.value} | {mark} | {result.detail} |")
    passed = sum(1 for r in results if r.passed)
    lines += ["", f"**{passed}/{len(results)} demonstrations passed.**", ""]
    return "\n".join(lines)


def write_report(out_dir: Path, results: list[DemoResult]) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "demos.json"
    md_path = out_dir / "demos.md"
    json_path.write_text(
        json.dumps(summarize(results), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(results), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}
