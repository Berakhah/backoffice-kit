import json
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

from bok_core.provenance.claim import Calibration, CalibrationState, Claim, Derivation, Method
from bok_core.provenance.source import FileSource, ModelSource

NOW = datetime.now(UTC)
SRC = FileSource(path="mcp.json", line=1)


def test_deterministic_claim_must_have_no_confidence() -> None:
    """I3. selector-drift 3.5 depends on this -- deterministic means uncalibrated, honestly."""
    Claim[int](value=1, source=SRC, method=Method.DETERMINISTIC, observed_at=NOW)
    with pytest.raises(ValidationError, match="DETERMINISTIC claims carry no confidence"):
        Claim[int](
            value=1, source=SRC, method=Method.DETERMINISTIC, confidence=0.9, observed_at=NOW
        )


def test_model_claim_without_confidence_is_not_a_fact() -> None:
    """I2. The UI must show it as unverified rather than as a number."""
    c = Claim[str](
        value="poisoned",
        source=ModelSource(ledger_call_id="c-1"),
        method=Method.MODEL,
        observed_at=NOW,
    )
    assert c.renders_as_fact() is False
    calibrated = Claim[str](
        value="poisoned",
        source=ModelSource(ledger_call_id="c-1"),
        method=Method.MODEL,
        confidence=0.9,
        calibration=Calibration(
            state=CalibrationState.CALIBRATED, basis="400 real fields", curve_id="v1", n=400
        ),
        observed_at=NOW,
    )
    assert calibrated.renders_as_fact() is True


def test_model_claim_with_confidence_but_no_calibration_is_not_a_fact() -> None:
    """00 B10: routing on an uncalibrated score is guessing while displaying a number."""
    c = Claim[str](
        value="x",
        source=ModelSource(ledger_call_id="c-1"),
        method=Method.MODEL,
        confidence=0.94,
        observed_at=NOW,
    )
    assert c.renders_as_fact() is False


def test_decimal_claim_serialises_as_string_never_float() -> None:
    """I5. model_dump_json is where the no-floats rule dies quietly (ledger-sense 4.1.2)."""
    c = Claim[Decimal](
        value=Decimal("1234.50"), source=SRC, method=Method.DETERMINISTIC, observed_at=NOW
    )
    payload = json.loads(c.model_dump_json())
    assert payload["value"] == "1234.50"
    assert isinstance(payload["value"], str)


def test_decimal_claim_stays_a_real_decimal_in_python_mode_dump() -> None:
    """I5's flip side. R1: the field_serializer originally ran on every mode
    (`when_used="always"`, pydantic's default), so python-mode `model_dump()` silently
    handed back a str where a caller reading `.value`'s declared type expects a Decimal.
    Scoping the serializer to `when_used="json"` is what this test pins."""
    c = Claim[Decimal](
        value=Decimal("1234.50"), source=SRC, method=Method.DETERMINISTIC, observed_at=NOW
    )
    value = c.model_dump()["value"]
    assert isinstance(value, Decimal)
    assert value == Decimal("1234.50")


def test_decimal_value_nested_in_parents_still_serialises_as_string() -> None:
    """I5 holds through the unbound-T path too: a Decimal-valued parent claim, held in the
    bare `parents: list[Claim]` field, must still come out of JSON as a string."""
    parent = Claim[Decimal](
        value=Decimal("9.99"), source=SRC, method=Method.DETERMINISTIC, observed_at=NOW
    )
    child = Claim[Decimal](
        value=Decimal("1.00"),
        source=SRC,
        method=Method.DETERMINISTIC,
        observed_at=NOW,
        parents=[parent],
    )
    dumped = json.loads(child.model_dump_json())
    assert dumped["parents"][0]["value"] == "9.99"
    assert isinstance(dumped["parents"][0]["value"], str)


def test_claim_is_frozen() -> None:
    """A plain attribute assignment must not bypass I1/I3 after validation already ran.
    R1: `det.confidence = 0.9` on a DETERMINISTIC claim worked silently before this."""
    det = Claim[int](value=1, source=SRC, method=Method.DETERMINISTIC, observed_at=NOW)
    with pytest.raises(ValidationError):
        det.confidence = 0.9


def test_derived_claim_inherits_unverified_ness_from_any_ancestor() -> None:
    """I7. R1: the single most consequential bug in the pre-revision plan.

    renders_as_fact() returned True for every method that was not MODEL, so ONE derive()
    hop laundered an uncalibrated model reading into a fact. The worked example in
    00 section 10.4 -- a definition-of-done item -- is exactly that shape.
    """
    shaky = Claim[float](
        value=0.7,
        source=ModelSource(ledger_call_id="c-1"),
        method=Method.MODEL,
        confidence=0.7,
        calibration=Calibration(state=CalibrationState.UNCALIBRATED, basis="none yet"),
        observed_at=NOW,
    )
    solid = Claim[int](value=1, source=SRC, method=Method.DETERMINISTIC, observed_at=NOW)
    assert shaky.renders_as_fact() is False
    assert solid.renders_as_fact() is True

    laundered = Claim[float](
        value=1.7,
        source=SRC,
        method=Method.DERIVED,
        confidence=0.7,
        observed_at=NOW,
        parents=[solid, shaky],
    )
    assert laundered.renders_as_fact() is False, "one derive() hop must not create a fact"


def test_derived_confidence_cannot_exceed_its_weakest_parent_even_when_hand_built() -> None:
    """I1. R1: the contract says bok-core enforces the invariants; the pre-revision plan
    enforced this one only inside derive(), which a consumer bypasses by constructing a
    Claim directly -- and consumers will, because Claim is a public Pydantic model."""
    weak = Claim[float](
        value=1.0,
        source=ModelSource(ledger_call_id="c"),
        method=Method.MODEL,
        confidence=0.3,
        calibration=Calibration(state=CalibrationState.CALIBRATED, basis="b", curve_id="v1", n=9),
        observed_at=NOW,
    )
    with pytest.raises(ValidationError, match="cannot exceed"):
        Claim[float](
            value=2.0,
            source=SRC,
            method=Method.DERIVED,
            confidence=0.99,
            observed_at=NOW,
            parents=[weak],
        )


def test_derivation_distinguishes_equally_deterministic_evidence() -> None:
    """agent-perimeter 8.1 / B9: schema-derived and description-inferred edges differ."""
    schema = Claim[bool](
        value=True,
        source=SRC,
        method=Method.DETERMINISTIC,
        derivation=Derivation.SCHEMA,
        observed_at=NOW,
    )
    described = schema.model_copy(update={"derivation": Derivation.DESCRIPTION})
    assert schema.derivation is Derivation.SCHEMA
    assert described.derivation is Derivation.DESCRIPTION
    assert schema.method is described.method
