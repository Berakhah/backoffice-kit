from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from bok_core.provenance.chain import derive, inherited_caveats
from bok_core.provenance.claim import Calibration, CalibrationState, Claim, Method
from bok_core.provenance.source import HumanSource, ModelSource

NOW = datetime.now(UTC)
CAL = Calibration(state=CalibrationState.CALIBRATED, basis="held-out set", curve_id="v1", n=180)


def _model(conf: float, caveat: str | None = None) -> Claim[float]:
    return Claim[float](
        value=1.0,
        source=ModelSource(ledger_call_id="c"),
        method=Method.MODEL,
        confidence=conf,
        calibration=CAL,
        observed_at=NOW,
        caveat=caveat,
    )


def test_derived_confidence_never_exceeds_the_weakest_parent() -> None:
    child = derive(2.0, [_model(0.9), _model(0.4)])
    assert child.method is Method.DERIVED
    assert child.confidence == pytest.approx(0.4)


def test_caveat_propagates_verbatim_to_children() -> None:
    child = derive(2.0, [_model(0.9, caveat="sample size 51")])
    assert "sample size 51" in inherited_caveats(child)


@given(
    levels=st.lists(st.lists(st.floats(0.01, 1.0), min_size=1, max_size=3), min_size=5, max_size=6)
)
def test_invariants_hold_over_branching_chains_at_depth_five(levels: list[list[float]]) -> None:
    """I6. A linear chain would run min() over one element per hop and prove nothing;
    real chains fan in, and 'n=180, private split' must survive to the last hop."""
    floor = min(min(level) for level in levels)
    node: Claim[float] = _model(levels[0][0], caveat="n=180, private split")
    for level in levels:
        siblings = [node, *(_model(c) for c in level)]
        node = derive(node.value + 1, siblings)
        assert node.confidence is not None
        assert node.confidence <= min(s.confidence or 1.0 for s in siblings) + 1e-9

    assert node.confidence is not None and node.confidence >= floor - 1e-9
    assert "n=180, private split" in inherited_caveats(node)


def test_derive_requires_at_least_one_parent() -> None:
    with pytest.raises(ValueError, match="at least one parent"):
        derive(1.0, [])


def test_own_caveat_comes_first_then_ancestors_verbatim() -> None:
    child = derive(2.0, [_model(0.9, caveat="parent says")], caveat="child says")
    assert inherited_caveats(child) == ["child says", "parent says"]


def test_shared_ancestor_caveat_is_reported_once() -> None:
    shared = _model(0.9, caveat="shared")
    left = derive(1.0, [shared])
    right = derive(2.0, [shared])
    top = derive(3.0, [left, right])
    assert inherited_caveats(top).count("shared") == 1


def test_parents_without_confidence_do_not_fabricate_one() -> None:
    human = Claim[float](
        value=1.0,
        source=HumanSource(who="a", at=NOW),
        method=Method.HUMAN,
        observed_at=NOW,
    )
    child = derive(2.0, [human])
    assert child.confidence is None
    assert child.calibration is None


def test_derived_from_uncalibrated_model_does_not_render_as_fact() -> None:
    """I7 through derive(): one hop must not launder an uncalibrated reading."""
    raw = Claim[float](
        value=1.0,
        source=ModelSource(ledger_call_id="c"),
        method=Method.MODEL,
        confidence=0.72,
        calibration=Calibration(state=CalibrationState.UNCALIBRATED, basis="synthetic only"),
        observed_at=NOW,
    )
    assert not derive(2.0, [raw]).renders_as_fact()
    assert derive(2.0, [_model(0.9)]).renders_as_fact()


def test_distinct_ancestors_with_identical_caveat_wording_are_both_kept() -> None:
    a = Claim[float](
        value=1.0,
        source=ModelSource(ledger_call_id="a"),
        method=Method.MODEL,
        confidence=0.9,
        calibration=CAL,
        observed_at=NOW,
        caveat="n=51",
    )
    b = Claim[float](
        value=1.0,
        source=ModelSource(ledger_call_id="b"),
        method=Method.MODEL,
        confidence=0.8,
        calibration=CAL,
        observed_at=NOW,
        caveat="n=51",
    )
    assert inherited_caveats(derive(2.0, [a, b])).count("n=51") == 2


def _unscored_model() -> Claim[float]:
    return Claim[float](
        value=1.0,
        source=ModelSource(ledger_call_id="u"),
        method=Method.MODEL,
        confidence=None,
        observed_at=NOW,
    )


def test_unscored_model_parent_makes_child_confidence_unknown() -> None:
    child = derive(2.0, [_unscored_model(), _model(0.9)])
    assert child.confidence is None
    assert child.calibration is None


def test_unscored_derived_parent_makes_child_confidence_unknown() -> None:
    unknown = derive(2.0, [_unscored_model()])
    assert derive(3.0, [unknown, _model(0.9)]).confidence is None


@pytest.mark.parametrize("kind", ["human", "deterministic"])
def test_deterministic_and_human_parents_do_not_lower_the_floor(kind: str) -> None:
    exact = Claim[float](
        value=1.0,
        source=HumanSource(who="a", at=NOW),
        method=Method.HUMAN if kind == "human" else Method.DETERMINISTIC,
        observed_at=NOW,
    )
    assert derive(2.0, [exact, _model(0.7)]).confidence == pytest.approx(0.7)


def test_claim_validator_rejects_scored_derived_over_unscored_model_parent() -> None:
    with pytest.raises(ValueError, match="unscored"):
        Claim[float](
            value=1.0,
            source=HumanSource(who="a", at=NOW),
            method=Method.DERIVED,
            confidence=0.9,
            observed_at=NOW,
            parents=[_unscored_model(), _model(0.9)],
        )
