"""Local HTTP surface for running the confidential-computing demos."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles

from .demos import DEMOS, run_all, run_one
from .reporting import result_to_dict, summarize
from .resources import web_dir


def create_app() -> FastAPI:
    app = FastAPI(
        title="Confidential Compute Demo",
        version="0.2.0",
        description="Homomorphic analytics, secret-sharing MPC, and remote attestation.",
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/demos")
    def demos() -> dict[str, Any]:
        catalogue = [demo() for demo in DEMOS]
        return {
            "demos": [
                {"id": r.id, "title": r.title, "kind": r.kind.value, "claim": r.claim}
                for r in catalogue
            ]
        }

    @app.post("/demos/{demo_id}/run")
    def run_named(demo_id: str) -> dict[str, Any]:
        result = run_one(demo_id)
        if result is None:
            raise HTTPException(status_code=404, detail="unknown demo")
        return result_to_dict(result)

    @app.get("/run")
    def run_everything() -> dict[str, Any]:
        return summarize(run_all())

    directory = web_dir()
    if directory.exists():
        app.mount("/", StaticFiles(directory=str(directory), html=True), name="web")

    return app
