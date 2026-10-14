import json
import time
from datetime import UTC, datetime
from decimal import Decimal

from bok_core.provenance.chain import derive
from bok_core.provenance.claim import Calibration, CalibrationState, Claim, Method
from bok_core.provenance.render import to_rail
from bok_core.provenance.source import BBox, DocumentSource, ModelSource

NOW = datetime.now(UTC)


def _doc() -> DocumentSource:
    return DocumentSource(path="a.pdf", page=1, bbox=BBox(x0=0, y0=0, x1=1, y1=1))


def test_rail_nests_parents_and_reports_depth() -> None:
    leaf = Claim[float](
        value=1.0,
        source=_doc(),
        method=Method.DETERMINISTIC,
        observed_at=NOW,
        caveat="page 1 only",
    )
    mid = derive(2.0, [leaf])
    top = derive(3.0, [mid])

    rail = to_rail(top)
    assert rail.depth == 3
    assert rail.root.parents[0].parents[0].source_kind == "document"
    assert "page 1 only" in rail.inherited_caveats


def test_rail_payload_keeps_a_decimal_as_a_string() -> None:
    """I5 at the boundary bok-ui consumes: RailNode.value is `object`."""
    c = Claim[Decimal](
        value=Decimal("48250.00"), source=_doc(), method=Method.DETERMINISTIC, observed_at=NOW
    )
    payload = json.loads(to_rail(c).model_dump_json())
    assert payload["root"]["value"] == "48250.00"
    assert isinstance(payload["root"]["value"], str)


def test_rail_does_not_blow_up_on_a_wide_shared_parent_dag() -> None:
    leaf = Claim[int](value=1, source=_doc(), method=Method.DETERMINISTIC, observed_at=NOW)
    node: Claim[int] = leaf
    for _ in range(12):
        node = derive(node.value + 1, [node, leaf])
    start = time.monotonic()
    rail = to_rail(node)
    assert time.monotonic() - start < 5
    assert rail.depth == 13


def test_uncalibrated_model_claim_is_flagged_not_a_fact() -> None:
    c = Claim[float](
        value=0.94,
        source=ModelSource(ledger_call_id="c-1"),
        method=Method.MODEL,
        confidence=0.94,
        calibration=Calibration(state=CalibrationState.UNCALIBRATED, basis="none yet"),
        observed_at=NOW,
    )
    rail = to_rail(c)
    assert rail.root.renders_as_fact is False
    assert rail.root.calibration_state == "UNCALIBRATED"
    assert rail.root.calibration_basis == "none yet"
    assert rail.root.confidence == 0.94


def test_derived_over_uncalibrated_model_does_not_render_as_fact() -> None:
    """I7 survives the rail: the derived node and the model node are both flagged."""
    m = Claim[float](
        value=0.72,
        source=ModelSource(ledger_call_id="c-2"),
        method=Method.MODEL,
        confidence=0.72,
        calibration=Calibration(state=CalibrationState.UNCALIBRATED, basis="synthetic"),
        observed_at=NOW,
    )
    rail = to_rail(derive(5.0, [m]))
    assert rail.root.renders_as_fact is False
    assert rail.root.parents[0].renders_as_fact is False


def test_rail_json_keys_are_pinned() -> None:
    """The contract with bok-ui and downstream shims: these exact keys, nothing else."""
    leaf = Claim[int](
        value=1,
        source=_doc(),
        method=Method.DETERMINISTIC,
        observed_at=NOW,
        caveat="c",
    )
    payload = json.loads(to_rail(derive(2, [leaf])).model_dump_json())
    assert set(payload) == {"root", "depth", "inherited_caveats"}
    assert set(payload["root"]) == {
        "value",
        "method",
        "derivation",
        "source_kind",
        "source",
        "confidence",
        "calibration_state",
        "calibration_basis",
        "renders_as_fact",
        "observed_at",
        "caveat",
        "parents",
    }
    assert payload["root"]["method"] == "DERIVED"
    assert payload["root"]["derivation"] is None
    assert payload["root"]["source_kind"] == "rule"
    assert payload["root"]["source"]["kind"] == "rule"
    assert payload["root"]["parents"][0]["method"] == "DETERMINISTIC"
    assert payload["root"]["parents"][0]["parents"] == []
    assert payload["inherited_caveats"] == ["c"]


def test_diamond_ancestor_caveat_reported_once_and_distinct_same_text_kept() -> None:
    leaf = Claim[int](
        value=1, source=_doc(), method=Method.DETERMINISTIC, observed_at=NOW, caveat="shared"
    )
    other = Claim[int](
        value=2, source=_doc(), method=Method.DETERMINISTIC, observed_at=NOW, caveat="shared"
    )
    diamond = derive(3, [derive(2, [leaf]), derive(2, [leaf])])
    assert to_rail(diamond).inherited_caveats == ["shared"]
    two = derive(3, [leaf, other])
    assert to_rail(two).inherited_caveats == ["shared", "shared"]
