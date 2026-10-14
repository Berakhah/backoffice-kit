"""SARIF emitter: logicalLocations-first, provenance travels with the finding."""

from __future__ import annotations

import hashlib
import json
import pathlib
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import jsonschema  # type: ignore[import-untyped]  # no stubs; test-only
import pytest
from pydantic import ValidationError

from bok_core.findings import Finding, Severity, to_sarif
from bok_core.provenance.claim import Claim, Method
from bok_core.provenance.render import to_rail
from bok_core.provenance.source import FileSource

NOW = datetime.now(UTC)
HERE = pathlib.Path(__file__).parent


def _claim() -> Claim[Any]:
    return Claim[Any](
        value=True,
        source=FileSource(path="mcp.json", line=12),
        method=Method.DETERMINISTIC,
        observed_at=NOW,
    )


def _finding(**over: object) -> Finding:
    kw: dict[str, object] = dict(
        id="AP001",
        severity=Severity.HIGH,
        title="Tool reads state and reaches the network",
        claim=_claim(),
        taxonomy_refs=["CWE-441", "OWASP-LLM-06"],
        logical_location="server/acme:tool/fetch",
        partial_fingerprints={"toolDescriptionHash": "abc123"},
        properties={"derivation": "SCHEMA"},
    )
    kw.update(over)
    return Finding(**kw)  # type: ignore[arg-type]


def _first(doc: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = doc["runs"][0]["results"][0]
    return result


def test_severity_ladder_values_are_pinned() -> None:
    assert [s.value for s in Severity] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def test_runtime_finding_uses_logical_location_not_physical() -> None:
    """agent-perimeter B7: a finding about a live server has no natural physicalLocation."""
    result = _first(to_sarif([_finding()], tool_name="agent-perimeter", tool_version="0.1.0"))
    loc = result["locations"][0]
    assert loc["logicalLocations"][0]["fullyQualifiedName"] == "server/acme:tool/fetch"
    assert "physicalLocation" not in loc


def test_no_location_when_logical_location_absent() -> None:
    result = _first(to_sarif([_finding(logical_location=None)], tool_name="t", tool_version="1"))
    assert "locations" not in result


def test_partial_fingerprints_enable_dedupe_across_scans() -> None:
    result = _first(to_sarif([_finding()], tool_name="agent-perimeter", tool_version="0.1.0"))
    assert result["partialFingerprints"]["toolDescriptionHash"] == "abc123"


def test_no_partial_fingerprints_key_when_empty() -> None:
    result = _first(to_sarif([_finding(partial_fingerprints={})], tool_name="t", tool_version="1"))
    assert "partialFingerprints" not in result


def test_severity_maps_onto_the_sarif_level_vocabulary() -> None:
    sevs = list(Severity)
    findings = [_finding(id=f"X{i}", severity=s) for i, s in enumerate(sevs)]
    doc = to_sarif(findings, tool_name="t", tool_version="0.1.0")
    levels = [r["level"] for r in doc["runs"][0]["results"]]
    assert levels == ["error", "error", "warning", "warning", "note"]
    ladder = [r["properties"]["bok_severity"] for r in doc["runs"][0]["results"]]
    assert ladder == [s.value for s in sevs]


def test_emitter_serves_a_data_quality_finding_with_no_scanner_vocabulary() -> None:
    """selector-drift emits quality violations through the same emitter."""
    f = _finding(
        id="SD-DQ-001",
        title="Null rate above contract threshold",
        logical_location="target/portal:field/claim_number",
        taxonomy_refs=[],
        properties={"threshold": 0.02, "observed": 0.11},
    )
    result = _first(to_sarif([f], tool_name="selector-drift", tool_version="0.1.0"))
    assert result["properties"]["observed"] == 0.11
    assert result["ruleId"] == "SD-DQ-001"


def test_every_result_carries_the_provenance_rail_of_its_claim() -> None:
    f = _finding()
    result = _first(to_sarif([f], tool_name="t", tool_version="1"))
    expected = to_rail(f.claim).model_dump(mode="json")
    assert result["properties"]["bok_provenance"] == expected
    assert set(expected) == {"root", "depth", "inherited_caveats"}


def test_decimal_claim_value_is_a_json_string_through_the_export() -> None:
    claim = Claim[Any](
        value=Decimal("12.50"),
        source=FileSource(path="a.csv", line=1),
        method=Method.DETERMINISTIC,
        observed_at=NOW,
    )
    doc = to_sarif([_finding(claim=claim)], tool_name="t", tool_version="1")
    assert _first(doc)["properties"]["bok_provenance"]["root"]["value"] == "12.50"
    json.dumps(doc)  # the whole document is JSON-serialisable


def test_bok_keys_cannot_be_overwritten_by_caller_properties() -> None:
    f = _finding(
        severity=Severity.LOW,
        properties={"bok_severity": "CRITICAL", "bok_provenance": "forged", "bok_taxonomy_refs": 1},
    )
    props = _first(to_sarif([f], tool_name="t", tool_version="1"))["properties"]
    assert props["bok_severity"] == "LOW"
    assert props["bok_provenance"] != "forged"
    assert props["bok_taxonomy_refs"] == ["CWE-441", "OWASP-LLM-06"]


def test_rules_are_deduplicated_and_ordered_by_first_appearance() -> None:
    fs = [_finding(id="B"), _finding(id="A"), _finding(id="B", title="again")]
    doc = to_sarif(fs, tool_name="t", tool_version="1")
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["B", "A"]
    assert len(doc["runs"][0]["results"]) == 3


def test_empty_findings_is_a_valid_empty_run() -> None:
    doc = to_sarif([], tool_name="t", tool_version="1")
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_properties_with_non_json_values_are_serialised_not_leaked_as_objects() -> None:
    f = _finding(properties={"when": NOW, "amount": Decimal("1.10")})
    props = _first(to_sarif([f], tool_name="t", tool_version="1"))["properties"]
    assert isinstance(props["when"], str)
    assert props["amount"] == "1.10"


def test_finding_is_a_closed_contract_type() -> None:
    with pytest.raises(ValidationError):
        _finding(unexpected="x")


def test_document_header_shape() -> None:
    doc = to_sarif([_finding()], tool_name="agent-perimeter", tool_version="0.1.0")
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    driver = doc["runs"][0]["tool"]["driver"]
    assert (driver["name"], driver["version"]) == ("agent-perimeter", "0.1.0")
    result = _first(doc)
    assert {"ruleId", "level", "message"} <= set(result)


def test_vendored_schema_matches_its_recorded_hash() -> None:
    raw = (HERE / "sarif-2.1.0.json").read_bytes()
    recorded = (HERE / "sarif-2.1.0.json.sha256").read_text(encoding="utf-8").split()[0]
    assert hashlib.sha256(raw).hexdigest() == recorded


def test_output_validates_against_the_sarif_2_1_0_schema() -> None:
    schema = json.loads((HERE / "sarif-2.1.0.json").read_text(encoding="utf-8"))
    fs = [
        _finding(),
        _finding(id="SD-1", severity=Severity.INFO, logical_location=None, partial_fingerprints={}),
    ]
    doc = to_sarif(fs, tool_name="t", tool_version="0.1.0")
    jsonschema.Draft7Validator(schema).validate(doc)
    jsonschema.Draft7Validator(schema).validate(to_sarif([], tool_name="t", tool_version="1"))
