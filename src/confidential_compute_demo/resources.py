"""Locate packaged data whether running from source or an installed wheel."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from pathlib import Path


@lru_cache
def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def packaged_path(name: str) -> Path:
    try:
        candidate = Path(str(resources.files("confidential_compute_demo") / "data" / name))
        if candidate.exists():
            return candidate
    except (ModuleNotFoundError, FileNotFoundError):
        pass
    return _repo_root() / "fixtures" / name


def web_dir() -> Path:
    try:
        candidate = Path(str(resources.files("confidential_compute_demo") / "web"))
        if (candidate / "index.html").exists():
            return candidate
    except (ModuleNotFoundError, FileNotFoundError):
        pass
    return _repo_root() / "web"
