"""Smoke-test the installed wheel from outside the source checkout."""

from __future__ import annotations

from confidential_compute_demo.benchmark import committed_ground_truth
from confidential_compute_demo.demos import ground_truth, run_all


def main() -> int:
    if ground_truth() != committed_ground_truth():
        print("ground truth drift")
        return 1
    results = run_all()
    if not all(r.passed for r in results):
        failed = [r.id for r in results if not r.passed]
        print(f"failed demos: {failed}")
        return 1
    print(f"ok: {len(results)} confidential-computing demos passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
