"""M2 - path-constraint extraction and priority (mini-BOND X2).

Implements BOND's three constraint classes and six semantic types (H-BOND.md §4.2).
A constraint is ``{"param", "semantic", "expr", "klass"}`` and maps 1:1 onto the
``external_finding.constraints[]`` schema field, consumed by directed fuzzing.

Constraint classes (mutation priority, highest first):
  * ``mandatory`` -- request cannot reach the sink without it (mutate first)
  * ``partial``   -- helps reach a deeper branch (mutate next)
  * ``none``      -- no effect on reachability (random mutation last)

Semantic types: ``string_eq`` / ``numeric_range`` / ``null_check`` / ``byte_check``
/ ``length_bound`` (our IoT supplement) / ``net_format`` (our IoT supplement).

All functions are pure and never raise; unparseable input degrades to ``none``.
"""

from __future__ import annotations

import re
from typing import Any

# higher number = higher mutation priority
KLASS_ORDER: dict[str, int] = {"mandatory": 0, "partial": 1, "none": 2}

_PARAM_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)")
_STRING_EQ_RE = re.compile(
    r'(?:deref|load|get)\s*\(\s*([^)]*?)\s*\)\s*==\s*["\']?([^"\']*?)["\']?\s*$', re.I)
_RANGE_RE = re.compile(r"[\[(]\s*[\d.]+\s*,\s*[\d.]+\s*[\])]")  # (0,1500] / [0,1500) / [1,2]
_RANGE_SYMBOL_RE = re.compile(r"[∈E]\s*\(?[\d.,\s]+\)?", re.I)  # ∈(0,1500] / E(0,1500]
_NULL_RE = re.compile(r'(\w+)\s*==\s*null|(\w+)\s*!=\s*null', re.I)


def parse_constraint_expr(expr: str, param: str = "") -> dict[str, str]:
    """Map a raw constraint expression to ``{semantic, klass, expr}``.

    Inference rules (mirror H-BOND.md §4.2 examples):
      * ``deref(v2)=="General"`` / ``load(v1)=="1"`` -> ``string_eq`` / ``mandatory``
      * ``atoi(v3)∈(0,1500]`` / ``v3∈(0,1500]`` -> ``numeric_range`` / ``mandatory``
      * ``v0==null`` / ``v1!=null``            -> ``null_check`` / ``mandatory``
      * a bare ``=="Yes"`` partial marker       -> ``string_eq`` / ``partial``
      * anything unrecognised                   -> ``other`` / ``none``
    """
    text = str(expr).strip()
    if not text:
        return {"semantic": "other", "klass": "none", "expr": text}

    m = _STRING_EQ_RE.search(text)
    if m:
        value = m.group(2)
        klass = "partial" if value.lower() in {"yes", "on", "true"} else "mandatory"
        return {"semantic": "string_eq", "klass": klass, "expr": text}

    if _RANGE_RE.search(text) or _RANGE_SYMBOL_RE.search(text):
        return {"semantic": "numeric_range", "klass": "mandatory", "expr": text}

    if _NULL_RE.search(text):
        return {"semantic": "null_check", "klass": "mandatory", "expr": text}

    if "==" in text or "!=" in text:
        return {"semantic": "string_eq", "klass": "mandatory", "expr": text}

    return {"semantic": "other", "klass": "none", "expr": text}


def extract_constraints(
    source: list[dict[str, Any]] | dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Normalise a candidate's raw constraint annotations into schema constraints.

    ``source`` may be:
      * a list of already-structured constraints ``{param, expr, klass?, semantic?}``
      * a dict with a ``constraints`` key (candidate shape)
      * None -> returns ``[]``

    Each produced item carries ``param`` / ``semantic`` / ``expr`` / ``klass``.
    Missing ``klass``/``semantic`` are inferred from the expression.
    """
    if source is None:
        return []
    items = source.get("constraints") or [] if isinstance(source, dict) else source

    out: list[dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        expr = str(item.get("expr") or item.get("constraint") or "")
        param = str(item.get("param") or _first_ident(expr) or "")
        parsed = parse_constraint_expr(expr, param)
        out.append({
            "param": param,
            "semantic": str(item.get("semantic") or parsed["semantic"]),
            "expr": expr,
            "klass": str(item.get("klass") or parsed["klass"]),
        })
    return out


def _first_ident(expr: str) -> str:
    m = _PARAM_RE.search(expr)
    return m.group(1) if m else ""


def priority_order(constraints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return ``constraints`` sorted by mutation priority (mandatory -> partial -> none)."""
    return sorted(
        constraints,
        key=lambda c: (KLASS_ORDER.get(str(c.get("klass", "none")), 9), str(c.get("param", ""))),
    )


__all__ = [
    "KLASS_ORDER",
    "parse_constraint_expr",
    "extract_constraints",
    "priority_order",
]
