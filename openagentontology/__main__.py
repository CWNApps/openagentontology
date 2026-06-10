"""__main__.py — `python -m openagentontology <path>` entrypoint (no install step).

With the package on PYTHONPATH:

    PYTHONPATH=. python -m openagentontology <path> [--out DIR] [--json] [--no-receipt]

The whole CLI lives in cli.py (arg parsing, artifact writing, the human summary). This module
is a one-line delegator so `python -m openagentontology ...` and `from openagentontology.cli
import main` are the exact same code path. It propagates cli.main's exit code:
    0  validation passed (ok)
    1  validation FAILED closed (error-level findings -- a fabricated/unsourced control or a
       structural break voided trust, pol.must_do.143)
    2  bad usage / the target path does not exist / an unexpected pipeline error

Stdlib only. No network.
"""
from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
