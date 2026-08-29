from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter, ValidationError

from bok_core.provenance.source import (
    BBox,
    DocumentSource,
    DomSource,
    FileSource,
    HumanSource,
    ModelSource,
    RuleSource,
    Source,
    UrlSource,
)

ADAPTER: TypeAdapter[Source] = TypeAdapter(Source)


def test_all_seven_variants_round_trip() -> None:
    now = datetime.now(UTC)
    variants: list[Source] = [
        FileSource(path="mcp.json", line=12),
        DocumentSource(path="app.pdf", page=2, bbox=BBox(x0=1, y0=2, x1=3, y1=4)),
        UrlSource(url="https://example.test/terms", retrieved_at=now),
        ModelSource(ledger_call_id="c-1"),
        HumanSource(who="reviewer", at=now),
        RuleSource(
            authority="Contract", citation="s5.2", confirmed_by="controller", confirmed_at=now
        ),
        DomSource(snapshot_id="s-1", selector="td:nth-child(3)", rung=2),
    ]
    for v in variants:
        assert ADAPTER.validate_json(ADAPTER.dump_json(v)) == v


def test_file_and_document_are_distinct_types() -> None:
    """Merged, 'no bbox because it is code' would be indistinguishable from
    'no bbox because extraction failed'."""
    assert FileSource(path="a.py", line=1).kind == "file"
    assert (
        DocumentSource(path="a.pdf", page=1, bbox=BBox(x0=0, y0=0, x1=1, y1=1)).kind == "document"
    )
    with pytest.raises(ValidationError):
        FileSource(path="a.pdf", line=1, page=2)  # type: ignore[call-arg]


def test_bbox_rejects_inverted_coordinates() -> None:
    with pytest.raises(ValidationError):
        BBox(x0=5, y0=0, x1=1, y1=1)
