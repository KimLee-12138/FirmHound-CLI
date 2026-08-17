"""Validate CVE benchmark fixtures against project schemas."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fsa.schemas.loader import validate

BENCHMARK_DIR = Path(__file__).parent.parent.parent / "benchmarks" / "CVEs"

CVE_IDS = [
    "CVE-2017-17215",
    "CVE-2019-17621",
    "CVE-2019-16920",
    "CVE-2020-9373",
    "CVE-2018-5767",
    "CVE-2020-10987",
    "CVE-2023-27021",
    "CVE-2021-31802",
    "CVE-2023-32154",
]


def _load(cve_id: str, name: str) -> dict:
    path = BENCHMARK_DIR / cve_id / name
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.mark.parametrize("cve_id", CVE_IDS)
def test_attack_surface_schema(cve_id: str) -> None:
    doc = _load(cve_id, "attack_surface.json")
    validate(doc, schema_name="attack_surface")


@pytest.mark.parametrize("cve_id", CVE_IDS)
def test_candidate_schema(cve_id: str) -> None:
    doc = _load(cve_id, "candidate.json")
    validate(doc, schema_name="candidate")


@pytest.mark.parametrize("cve_id", CVE_IDS)
def test_verdict_schema(cve_id: str) -> None:
    doc = _load(cve_id, "verdict.json")
    validate(doc, schema_name="verdict")


def test_all_cve_directories_exist() -> None:
    for cve_id in CVE_IDS:
        assert (BENCHMARK_DIR / cve_id).is_dir()
        assert (BENCHMARK_DIR / cve_id / "attack_surface.json").exists()
        assert (BENCHMARK_DIR / cve_id / "candidate.json").exists()
        assert (BENCHMARK_DIR / cve_id / "verdict.json").exists()


def test_cve_metadata_consistency() -> None:
    for cve_id in CVE_IDS:
        candidate = _load(cve_id, "candidate.json")
        verdict = _load(cve_id, "verdict.json")
        assert candidate["metadata"]["cve_id"] == cve_id
        assert verdict["verdicts"][0]["candidate_id"] == candidate["candidate_id"]
