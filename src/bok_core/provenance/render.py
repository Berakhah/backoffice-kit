"""Serialisation for bok-ui's <ProvenanceRail>. Parents nest, top to bottom."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, field_serializer

from bok_core.provenance.chain import inherited_caveats
from bok_core.provenance.claim import Claim


class RailNode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: object
    method: str
    derivation: str | None
    source_kind: str
    source: dict[str, object]
    confidence: float | None
    calibration_state: str | None
    calibration_basis: str | None
    renders_as_fact: bool
    observed_at: datetime
    caveat: str | None
    parents: list[RailNode]

    @field_serializer("value", when_used="json")
    def _serialise_value(self, v: object) -> object:
        # I5 at the rail boundary: `object` gives pydantic no declared type to lean on,
        # so pin the Decimal-as-string rule here rather than rely on inference.
        return str(v) if isinstance(v, Decimal) else v


class RailPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    root: RailNode
    depth: int
    inherited_caveats: list[str]


def _build(claim: Claim, memo: dict[str, tuple[RailNode, int]]) -> tuple[RailNode, int]:  # type: ignore[type-arg]
    """Return (node, depth), memoised on structural identity.

    A chain is a DAG; expanding it naively re-walks every shared subtree. Pydantic
    revalidates parents into fresh instances, so id() cannot recognise a shared ancestor
    (see Claim.parents); the serialised subtree can.
    """
    key = claim.model_dump_json()
    hit = memo.get(key)
    if hit is not None:
        return hit
    built = [_build(p, memo) for p in claim.parents]
    node = RailNode(
        value=claim.value,
        method=str(claim.method),
        derivation=str(claim.derivation) if claim.derivation else None,
        source_kind=claim.source.kind,
        source=claim.source.model_dump(mode="json"),
        confidence=claim.confidence,
        calibration_state=str(claim.calibration.state) if claim.calibration else None,
        calibration_basis=claim.calibration.basis if claim.calibration else None,
        renders_as_fact=claim.renders_as_fact(),
        observed_at=claim.observed_at,
        caveat=claim.caveat,
        parents=[n for n, _ in built],
    )
    result = (node, 1 + max((d for _, d in built), default=0))
    memo[key] = result
    return result


def to_rail(claim: Claim) -> RailPayload:  # type: ignore[type-arg]
    root, depth = _build(claim, {})
    return RailPayload(root=root, depth=depth, inherited_caveats=inherited_caveats(claim))
