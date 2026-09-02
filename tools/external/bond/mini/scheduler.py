"""Priority-ordered seed generation for directed fuzzing (mini-BOND X2).

Replaces BOND's patched-BooFuzz mutation core. It generates bounded seed request
sequences honouring constraint priority for the built-in HTTP transport. The generated
seeds are plain request parameters, never transport or shell command lines.
"""

from __future__ import annotations

from typing import Any

from tools.external.bond.mini.constraint import priority_order

# Satisfier values per semantic type. Concrete, benign, non-executable.
_SATISFIERS: dict[str, list[str]] = {
    "string_eq": ["1", "General", "Yes", "admin"],
    "numeric_range": ["10", "500", "1500"],
    "null_check": ["x"],  # a non-empty value satisfies "!= null"
    "byte_check": ["0x00", "0xff"],
    "length_bound": ["AAAA"],
    "net_format": ["192.168.1.1"],
    "other": ["x"],
}


def generate_seeds(
    constraints: list[dict[str, Any]],
    *,
    n_variants: int = 3,
) -> list[str]:
    """Generate ``n_variants`` seed request bodies honouring constraint priority.

    Strategy (H-BOND.md §4.3):
      1) every ``mandatory`` param gets a satisfier value (all variants),
      2) ``partial`` params take a satisfier in some variants and not others,
      3) ``none`` params get a random token.
    Returns a list of ``key=value&...`` request strings. Never raises.
    """
    ordered = priority_order(constraints)
    mand = [c for c in ordered if c.get("klass") == "mandatory"]
    part = [c for c in ordered if c.get("klass") == "partial"]
    none = [c for c in ordered if c.get("klass") == "none"]

    seeds: list[str] = []
    for v in range(max(1, n_variants)):
        pairs: list[str] = []
        for c in mand:
            pairs.append(f"{c.get('param')}={_satisfy(c)}")
        # partial: satisfy on even variants, leave out on odd (explore deeper branch)
        if v % 2 == 0:
            for c in part:
                pairs.append(f"{c.get('param')}={_satisfy(c)}")
        for c in none:
            pairs.append(f"{c.get('param')}=x")
        seeds.append("&".join(pairs))
    return seeds


def _satisfy(constraint: dict[str, Any]) -> str:
    semantic = str(constraint.get("semantic") or "other")
    opts = _SATISFIERS.get(semantic, ["x"])
    expr = str(constraint.get("expr") or "")
    # prefer a literal value present in the expression, else the satisfier list.
    for tok in expr.replace("'", " ").replace('"', " ").split():
        if tok and tok not in {"==", "!=", "(", ")", "∈", "E", "null"}:
            return tok.strip("'\"")
    return opts[0]


__all__ = ["generate_seeds"]
