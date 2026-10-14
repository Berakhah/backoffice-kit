from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from bok_core.boundary.redact import RedactionFailed, RedactionResult, redact
from bok_core.boundary.sensitivity import Labelled, Sensitivity

KEY = b"test-key; real keys come from BOK_REDACTION_KEY and are never committed"

DOC = (
    "Invoice from ana@example.test, phone 555-010-0100, routing 021000021, "
    "account 12345678. Contact ana@example.test again."
)


def test_identifiers_are_replaced_by_keyed_stable_surrogates() -> None:
    r = redact(Labelled(DOC, Sensitivity.CLIENT_CONFIDENTIAL), key=KEY)
    for identifier in ("ana@example.test", "021000021", "12345678"):
        assert identifier not in r.text
    # One distinct email seen twice -> one surrogate, used twice. Joins survive.
    assert r.surrogate_count["email"] == 1
    only = redact(Labelled("ana@example.test", Sensitivity.PUBLIC), key=KEY).text
    assert r.text.count(only) == 2


def test_the_result_never_carries_the_identifiers_it_removed() -> None:
    """R1: the result exposed `surrogates: dict[original -> surrogate]`, so the object
    handed back from redaction contained every identifier it had just removed -- and
    egress.guard_write() takes that object as an argument. One log line, one cache write
    or one traceback re-leaked the whole document."""
    r = redact(Labelled(DOC, Sensitivity.CLIENT_CONFIDENTIAL), key=KEY)
    blob = r.model_dump_json() + repr(r) + str(r)
    for identifier in ("ana@example.test", "021000021", "12345678", "555-010-0100"):
        assert identifier not in blob


def test_surrogates_are_keyed_so_a_redacted_document_is_not_a_lookup_table() -> None:
    """R1: a surrogate of sha256(identifier)[:8] is reversible by dictionary attack for
    exactly the classes that matter -- the entire 9-digit routing space enumerates in
    seconds, and so does any phone number."""
    one = redact(Labelled("routing 021000021", Sensitivity.CLIENT_CONFIDENTIAL), key=b"k1")
    two = redact(Labelled("routing 021000021", Sensitivity.CLIENT_CONFIDENTIAL), key=b"k2")
    assert one.text != two.text


def test_verification_re_runs_detection_and_catches_what_substitution_missed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R1: THE test the pre-revision plan did not have.

    The old verification asked 'is any string I replaced still present?' -- a tautology,
    since replacement is what removed them. It could only be made to fail by a
    `_force_leak=` argument that re-appended the secret by hand, and that argument sat in
    production code as a documented way to write a raw secret into a redacted document.

    Verification now re-runs every DETECTOR over the output. Here substitution is
    disabled for one class while detection stays on -- simulating a genuine miss, which
    is the failure that actually occurs: an overlapping match, a split token, a pattern
    that does not generalise to the next document.
    """
    import bok_core.boundary.redact as m

    monkeypatch.setitem(m._SUBSTITUTION_DISABLED, "routing", True)
    r = redact(Labelled("routing 021000021", Sensitivity.CLIENT_CONFIDENTIAL), key=KEY)
    assert r.verified is False
    assert "routing" in r.failures
    assert "021000021" in r.text  # it really did survive


def test_an_unverified_result_cannot_be_turned_into_a_payload() -> None:
    """`verified` is not a bool a caller can forget to read: the only route from a result
    to a usable payload raises when verification failed."""
    bad = RedactionResult(
        text="acct 12345678", verified=False, surrogate_count={}, failures=["account"]
    )
    with pytest.raises(RedactionFailed, match="account"):
        bad.labelled()


def test_clean_document_verifies_and_relabels_itself() -> None:
    r = redact(Labelled("Total due 1,240.00 for line item 7.", Sensitivity.SYNTHETIC), key=KEY)
    assert r.verified is True
    assert r.failures == []
    assert r.labelled().sensitivity is Sensitivity.REDACTED


def test_an_unkeyed_call_is_refused_rather_than_silently_weakened() -> None:
    with pytest.raises(ValueError, match="requires a key"):
        redact(Labelled(DOC, Sensitivity.CLIENT_CONFIDENTIAL), key=b"")


def test_declared_coverage_matches_the_detectors_that_exist() -> None:
    """00 section 4.2 names six identifier classes. Whichever ship, the gap is DECLARED:
    an undetected class is a hole in the boundary, and naming it is the difference
    between a limitation and a lie."""
    import bok_core.boundary.redact as m

    assert set(m._DETECTORS) == set(m.COVERED)
    assert set(m.NOT_COVERED) == {"person_name", "address"}
    assert not set(m.COVERED) & set(m.NOT_COVERED)


# --- Beyond the brief -------------------------------------------------------------------


def test_methodology_declares_every_covered_and_uncovered_class() -> None:
    """The declared list lives in two places; this keeps docs/methodology.md from drifting
    away from the tuples the code actually ships."""
    import bok_core.boundary.redact as m

    doc = (Path(__file__).parents[2] / "docs" / "methodology.md").read_text(encoding="utf-8")
    for kind in (*m.COVERED, *m.NOT_COVERED):
        assert f"`{kind}`" in doc, kind


_KINDS = st.sampled_from(["email", "phone", "iban", "card", "routing", "tax_id", "account"])


@given(kind=_KINDS, original=st.text(min_size=1, max_size=40), key=st.binary(min_size=1))
def test_a_surrogate_never_looks_like_an_identifier(kind: str, original: str, key: bytes) -> None:
    """A surrogate that re-triggers a detector would fail verification on a CORRECT
    redaction (or be re-substituted by a later detector). A hex digest contains runs of
    8-10 decimal digits a few percent of the time, so the alphabet must carry no digits."""
    import bok_core.boundary.redact as m

    surrogate = m._surrogate(kind, original, key)
    assert not any(p.search(surrogate) for p in m._DETECTORS.values())


def test_same_key_same_input_same_surrogate() -> None:
    a = redact(Labelled("routing 021000021", Sensitivity.CLIENT_CONFIDENTIAL), key=KEY)
    b = redact(Labelled("routing 021000021", Sensitivity.CLIENT_CONFIDENTIAL), key=KEY)
    assert a.text == b.text
    assert a.surrogate_count == {"routing": 1}


_IDENTIFIERS = st.one_of(
    st.from_regex(r"\A[a-z]{1,8}@[a-z]{1,8}\.test\Z"),
    st.from_regex(r"\A[0-9]{3}-[0-9]{3}-[0-9]{4}\Z"),
    st.from_regex(r"\AGB[0-9]{2}[A-Z0-9]{14}\Z"),
    st.from_regex(r"\A[0-9]{4} [0-9]{4} [0-9]{4} [0-9]{4}\Z"),
    st.from_regex(r"\A[0-9]{9}\Z"),
    st.from_regex(r"\A[0-9]{2}-[0-9]{7}\Z"),
    st.from_regex(r"\A[0-9]{3}-[0-9]{2}-[0-9]{4}\Z"),
    st.from_regex(r"\A[0-9]{8}\Z"),
)


@given(ids=st.lists(_IDENTIFIERS, min_size=1, max_size=6))
def test_any_document_of_covered_identifiers_redacts_and_verifies(ids: list[str]) -> None:
    doc = "Ref " + " and ".join(ids) + " end."
    r = redact(Labelled(doc, Sensitivity.CLIENT_CONFIDENTIAL), key=KEY)
    assert r.verified is True, r.failures
    for identifier in ids:
        assert identifier not in r.text
    assert sum(r.surrogate_count.values()) == len(set(ids))
