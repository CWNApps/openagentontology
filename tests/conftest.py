"""conftest.py — make the test suite runnable with NO install step.

`pytest` from the repo root (or `python -m pytest tests`) works because this file puts the
repo root on sys.path so `import openagentontology` resolves to the source tree, exactly the
way the package is meant to run: PYTHONPATH=<repo> python -m openagentontology <path>.

Shared fixtures:
    repo_root      the package repo root (Path)
    sample_dir     examples/sample_agent (the dogfood corpus)
    receipt_key    an isolated, throwaway Ed25519 key path under tmp (so tests never touch
                   ~/.openagentontology and stay hermetic/parallel-safe)
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return _REPO_ROOT


@pytest.fixture(scope="session")
def sample_dir(repo_root: Path) -> Path:
    d = repo_root / "examples" / "sample_agent"
    assert d.is_dir(), f"missing dogfood corpus: {d}"
    return d


@pytest.fixture()
def receipt_key(tmp_path: Path) -> str:
    """A fresh, isolated signing-key path per test (keeps the suite hermetic + deterministic)."""
    return str(tmp_path / "receipt_ed25519.pem")
