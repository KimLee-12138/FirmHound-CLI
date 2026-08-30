"""M2 constraint extraction (H-BOND.md §8.2).

Covers the three inference rules and the mandatory > partial > none priority ordering.
"""

from __future__ import annotations

from tools.external.bond.mini.constraint import (
    KLASS_ORDER,
    extract_constraints,
    parse_constraint_expr,
    priority_order,
)


def test_string_eq_mandatory() -> None:
    c = parse_constraint_expr('deref(v2)=="General"')
    assert c["semantic"] == "string_eq"
    assert c["klass"] == "mandatory"


def test_numeric_range() -> None:
    c = parse_constraint_expr("atoi(v3)∈(0,1500]")
    assert c["semantic"] == "numeric_range"
    assert c["klass"] == "mandatory"


def test_null_check() -> None:
    c = parse_constraint_expr("v0==null && v1!=null")
    assert c["semantic"] == "null_check"
    assert c["klass"] == "mandatory"


def test_partial_string_eq() -> None:
    # a "Yes" equality is a partial (deeper-branch) constraint per the paper example
    c = parse_constraint_expr('deref(v4)=="Yes"')
    assert c["semantic"] == "string_eq"
    assert c["klass"] == "partial"


def test_no_constraint_is_none() -> None:
    c = parse_constraint_expr("")
    assert c["klass"] == "none"
    assert c["semantic"] == "other"


def test_priority_ordering() -> None:
    constraints = [
        {"param": "Server", "semantic": "net_format", "expr": "ipv4", "klass": "none"},
        {"param": "STATIC", "semantic": "string_eq", "expr": "=='Yes'", "klass": "partial"},
        {"param": "Save", "semantic": "string_eq", "expr": "=='1'", "klass": "mandatory"},
    ]
    ordered = priority_order(constraints)
    klasses = [c["klass"] for c in ordered]
    assert klasses == ["mandatory", "partial", "none"]


def test_extract_constraints_from_candidate() -> None:
    candidate = {
        "constraints": [
            {"param": "MTU", "expr": "(0,1500]"},
            {"param": "Mode", "expr": "=='General'"},
        ]
    }
    out = extract_constraints(candidate)
    assert len(out) == 2
    by_param = {c["param"]: c for c in out}
    assert by_param["MTU"]["semantic"] == "numeric_range"
    assert by_param["Mode"]["semantic"] == "string_eq"


def test_extract_constraints_none() -> None:
    assert extract_constraints(None) == []
    assert extract_constraints({}) == []
