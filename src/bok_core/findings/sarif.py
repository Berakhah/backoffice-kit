"""SARIF 2.1.0 emitter.

SARIF was designed for static analysis of source files. A runtime finding about a live
server has no natural physicalLocation, so logicalLocations and partialFingerprints are
first-class here (agent-perimeter B7).

SENSITIVITY: the output of ``to_sarif`` is CLIENT data. Every result carries
``properties.bok_provenance`` -- the full claim chain, including cell values and source
locators -- by design, because an export that strips the origin defeats the purpose. It
must therefore be written through ``bok_core.boundary.egress`` and never sent to a log,
a webhook, or a metrics label.
"""

from __future__ import annotations

from typing import Any, Final

from bok_core.findings.finding import Finding
from bok_core.findings.severity import Severity
from bok_core.provenance.render import to_rail

SARIF_SCHEMA: Final = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION: Final = "2.1.0"

# SARIF's `level` collapses the ladder; the ladder value rides on properties.bok_severity.
_LEVEL: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "note",
}


def _rule(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "name": f.title,
        "shortDescription": {"text": f.title},
        "properties": {"taxonomyRefs": list(f.taxonomy_refs)},
    }


def _result(f: Finding) -> dict[str, Any]:
    # Caller properties first, bok_* last: a caller cannot overwrite the ladder value
    # or the evidence chain. JSON mode so Decimal/datetime values are plain JSON.
    properties: dict[str, Any] = f.model_dump(mode="json")["properties"] | {
        "bok_severity": f.severity.value,
        "bok_provenance": to_rail(f.claim).model_dump(mode="json"),
        "bok_taxonomy_refs": list(f.taxonomy_refs),
    }
    result: dict[str, Any] = {
        "ruleId": f.id,
        "level": _LEVEL[f.severity],
        "message": {"text": f.title},
    }
    if f.logical_location is not None:
        result["locations"] = [{"logicalLocations": [{"fullyQualifiedName": f.logical_location}]}]
    if f.partial_fingerprints:
        result["partialFingerprints"] = dict(f.partial_fingerprints)
    result["properties"] = properties
    return result


def to_sarif(findings: list[Finding], *, tool_name: str, tool_version: str) -> dict[str, Any]:
    """SARIF 2.1.0. logicalLocations, partialFingerprints and properties are
    first-class, not only physicalLocation.

    Every result carries properties.bok_provenance = to_rail(finding.claim) and
    properties.bok_severity = the ladder value. The result is CLIENT data (see the
    module docstring): route it through egress, never into logs or webhooks."""
    rules: dict[str, dict[str, Any]] = {}
    for f in findings:
        rules.setdefault(f.id, _rule(f))
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": [_result(f) for f in findings],
            }
        ],
    }
