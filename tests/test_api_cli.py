from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from confidential_compute_demo.api import create_app
from confidential_compute_demo.cli import main


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_healthz(client: TestClient) -> None:
    assert client.get("/healthz").json()["status"] == "ok"


def test_demos_listing(client: TestClient) -> None:
    assert len(client.get("/demos").json()["demos"]) == 7


def test_run_one(client: TestClient) -> None:
    body = client.post("/demos/mpc-secure-average/run").json()
    assert body["passed"] is True
    assert client.post("/demos/nope/run").status_code == 404


def test_run_all(client: TestClient) -> None:
    assert client.get("/run").json()["passed"] == 7


def test_dashboard(client: TestClient) -> None:
    assert client.get("/").status_code == 200


def _capture(capsys: pytest.CaptureFixture[str]) -> object:
    return json.loads(capsys.readouterr().out)


def test_cli_demo_all(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["demo", "all"]) == 0
    assert _capture(capsys)["passed"] == 7


def test_cli_demo_named(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["demo", "sealed-computation"]) == 0
    assert _capture(capsys)["id"] == "sealed-computation"


def test_cli_demo_unknown(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["demo", "nope"]) == 2


def test_cli_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["report", "--out", str(tmp_path)]) == 0
    assert Path(_capture(capsys)["json"]).exists()


def test_cli_benchmark(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["benchmark", "--iterations", "2", "--out", str(tmp_path)]) == 0
    assert _capture(capsys)["deterministic"] is True
