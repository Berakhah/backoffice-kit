"""A typed finding carrying a Claim, so every asserted fact opens the provenance rail."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from bok_core.findings.severity import Severity
from bok_core.provenance.claim import Claim


class Finding(BaseModel):
    # A contract type: a misspelt field must fail loudly, not vanish.
    model_config = ConfigDict(extra="forbid")

    id: str
    severity: Severity
    title: str
    claim: Claim[Any]
    taxonomy_refs: list[str] = []
    logical_location: str | None = None
    partial_fingerprints: dict[str, str] = {}
    properties: dict[str, Any] = {}
