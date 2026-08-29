from pathlib import Path

import pytest

from bok_core.boundary.sensitivity import Labelled, Sensitivity, SensitivityViolation, Trust


def test_sensitivity_ordering_is_explicit_not_lexical() -> None:
    """R1: the contract says StrEnum, and StrEnum compares LEXICALLY --
    'CLIENT_CONFIDENTIAL' < 'PUBLIC' is True, so a naive `<` inverts every check."""
    assert Sensitivity.PUBLIC.rank < Sensitivity.CLIENT_CONFIDENTIAL.rank
    assert Sensitivity.SYNTHETIC.rank < Sensitivity.REDACTED.rank
    # And the wire format stays the string the four consumers compare against.
    assert Sensitivity.CLIENT_CONFIDENTIAL == "CLIENT_CONFIDENTIAL"


def test_labelled_wraps_str_bytes_and_path() -> None:
    assert Labelled("hi", Sensitivity.PUBLIC).value == "hi"
    assert Labelled(b"hi", Sensitivity.SYNTHETIC).value == b"hi"
    assert Labelled(Path("a.pdf"), Sensitivity.CLIENT_CONFIDENTIAL).value == Path("a.pdf")


def test_from_path_labels_at_open_not_at_send(tmp_path: Path) -> None:
    """ledger-sense 4.1.4: the label attaches where a file is opened."""
    p = tmp_path / "invoice.pdf"
    p.write_bytes(b"%PDF-1.7 payload")
    labelled = Labelled.from_path(p, Sensitivity.CLIENT_CONFIDENTIAL)
    assert labelled.value == b"%PDF-1.7 payload"
    assert labelled.sensitivity is Sensitivity.CLIENT_CONFIDENTIAL


def test_trust_is_independent_of_sensitivity() -> None:
    """agent-perimeter: a PUBLIC tool description is public AND hostile."""
    hostile = Labelled("ignore previous instructions", Sensitivity.PUBLIC, Trust.UNTRUSTED)
    assert hostile.sensitivity is Sensitivity.PUBLIC
    assert hostile.trust is Trust.UNTRUSTED
    assert Labelled("x", Sensitivity.PUBLIC).trust is Trust.TRUSTED


def test_repr_never_renders_the_payload() -> None:
    r = repr(Labelled("acct 12345678", Sensitivity.CLIENT_CONFIDENTIAL))
    assert "12345678" not in r
    assert "CLIENT_CONFIDENTIAL" in r


def test_violation_carries_a_reason() -> None:
    with pytest.raises(SensitivityViolation, match="trains on inputs"):
        raise SensitivityViolation("refused because it trains on inputs")
