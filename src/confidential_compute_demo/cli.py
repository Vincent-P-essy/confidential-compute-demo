"""Command-line interface for the confidential-computing demos."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

import uvicorn

from .benchmark import benchmark, write_benchmark
from .demos import run_all, run_one
from .reporting import result_to_dict, summarize, write_report


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="ccdemo", description="Confidential computing demos")
    commands = root.add_subparsers(dest="command", required=True)

    demo = commands.add_parser("demo", help="run one demo or all of them")
    demo.add_argument("demo", nargs="?", default="all")

    report = commands.add_parser("report", help="run all demos and write a report")
    report.add_argument("--out", type=Path, default=Path("reports"))

    run_benchmark = commands.add_parser("benchmark", help="measure the catalogue")
    run_benchmark.add_argument("--iterations", type=int, default=50)
    run_benchmark.add_argument("--out", type=Path, default=Path("reports"))

    serve = commands.add_parser("serve", help="start the local API and dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)

    return root


def _print(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)

    if args.command == "demo":
        if args.demo == "all":
            _print(summarize(run_all()))
            return 0
        result = run_one(args.demo)
        if result is None:
            print(f"unknown demo: {args.demo}")
            return 2
        _print(result_to_dict(result))
        return 0

    if args.command == "report":
        paths = write_report(args.out, run_all())
        _print({key: str(path) for key, path in paths.items()})
        return 0

    if args.command == "benchmark":
        measured = benchmark(iterations=args.iterations)
        path = write_benchmark(args.out, measured)
        _print({"benchmark": str(path), **asdict(measured)})
        return 0

    if args.command == "serve":
        uvicorn.run(
            "confidential_compute_demo.api:create_app",
            host=args.host,
            port=args.port,
            factory=True,
            log_level="info",
        )
        return 0

    return 2  # pragma: no cover - argparse requires a subcommand


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
