"""Composition. A Claim derived from Claims keeps its parents, and cannot
claim more confidence than they permit."""

from __future__ import annotations

from datetime import UTC, datetime

from bok_core.provenance.claim import Claim, Method
from bok_core.provenance.source import RuleSource


def derive[T](
    value: T,
    parents: list[Claim],  # type: ignore[type-arg]
    *,
    caveat: str | None = None,
    observed_at: datetime | None = None,
    who: str = "derivation",
    authority: str = "derivation",
) -> Claim[T]:
    """Build a DERIVED claim whose confidence is floored by its weakest parent (I1).

    Parents without a confidence (DETERMINISTIC, HUMAN) do not lower the floor; if no
    parent has one, the child has none rather than an invented one.
    """
    if not parents:
        raise ValueError("a DERIVED claim needs at least one parent")

    # An unscored MODEL or DERIVED parent makes the child's confidence unknown (None):
    # skipping it would let a scored sibling vouch for a reading nobody scored.
    # DETERMINISTIC and HUMAN parents carry no confidence by design and do not lower the floor.
    unknown = any(
        p.confidence is None and p.method in (Method.MODEL, Method.DERIVED) for p in parents
    )
    scored = [(p.confidence, p) for p in parents if p.confidence is not None]
    floor = None if unknown else min(scored, key=lambda cp: cp[0], default=None)
    weakest = floor[1] if floor else None
    when = observed_at or datetime.now(UTC)

    return Claim[T](
        value=value,
        # A deterministic derivation rule is not a human; RuleSource carries the authority.
        source=RuleSource(authority=authority, citation=who, confirmed_by=who, confirmed_at=when),
        method=Method.DERIVED,
        confidence=weakest.confidence if weakest else None,
        calibration=weakest.calibration if weakest else None,
        observed_at=when,
        parents=list(parents),
        caveat=caveat,
    )


def inherited_caveats(claim: Claim) -> list[str]:  # type: ignore[type-arg]
    """Every caveat reachable from this claim: its own first, then ancestors' verbatim (I4).

    Computed by walking the parent DAG rather than copied down at derive() time, so a
    caveat always carries its original wording. Pydantic revalidates parents into fresh
    instances, so id() cannot identify a shared ancestor; structural identity
    (model_dump_json, which includes the whole subtree) does. A diamond ancestor is
    reported once, while two distinct ancestors that happen to share wording are both kept.
    """
    out: list[str] = []
    seen: set[str] = set()

    def walk(node: Claim) -> None:  # type: ignore[type-arg]
        key = node.model_dump_json()
        if key in seen:
            return
        seen.add(key)
        if node.caveat:
            out.append(node.caveat)
        for parent in node.parents:
            walk(parent)

    walk(claim)
    return out
