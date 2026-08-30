#!/usr/bin/env python3
"""Debug entry point for a single external analyzer (or all of them).

This is the F5 manual trigger. It does NOT touch the orchestrator; it runs an
analyzer directly against a run directory so a developer can iterate quickly.

Examples
--------
    # Run only SaTC against an existing run (writes artifacts/external_findings/satc.json)
    python scripts/run_external.py --tool satc --run-dir runs/dir859_full

    # Run every enabled analyzer in the run's config
    python scripts/run_external.py --tool all --run-dir runs/dir859_full

    # Point at a specific rootfs and config (bypasses auto-discovery)
    python scripts/run_external.py --tool satc --run-dir runs/demo \\
        --config config/dev.yaml

The tool is gated by ``config/dev.yaml`` ``external.<tool>.enabled``. With the
default config everything is disabled, so the command prints a ``skipped`` record
and exits 0 -- that is the expected degradation behavior, not an error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Make the project root importable when invoked as a script.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tools.external.adapter import run_bond, run_firmrec, run_klee, run_satc  # noqa: E402
from tools.external.run_all import run_all  # noqa: E402


_DISPATCH = {
    "satc": run_satc,
    "firmrec": run_firmrec,
    "klee": run_klee,
    "bond": run_bond,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an external analyzer against a run directory.")
    parser.add_argument("--tool", required=True, choices=["satc", "firmrec", "klee", "bond", "all"])
    parser.add_argument("--run-dir", required=True, help="Pipeline run directory.")
    parser.add_argument("--config", default=None, help="Optional YAML config overriding config/dev.yaml.")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print(f"error: run-dir does not exist: {run_dir}", file=sys.stderr)
        return 2

    if args.tool == "all":
        result = run_all(run_dir, args.config)
    else:
        result = _DISPATCH[args.tool](run_dir, args.config)

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
