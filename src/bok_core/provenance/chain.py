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

    scored = [p for p in parents if p.confidence is not None]
    weakest = min(
        scored, key=lambda p: p.confidence if p.confidence is not None else 1.0, default=None
    )
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
    caveat is never duplicated per hop and always carries its original wording. Pydantic revalidates
    parents into fresh instances, so a shared ancestor is not the same object in each
    branch (id() dedup fails); identical caveat text is therefore reported once.
    """
    out: list[str] = []

    def walk(node: Claim) -> None:  # type: ignore[type-arg]
        if node.caveat and node.caveat not in out:
            out.append(node.caveat)
        for parent in node.parents:
            walk(parent)

    walk(claim)
    return out
