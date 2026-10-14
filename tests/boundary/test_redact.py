import re
import time
from collections import Counter
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from bok_core.boundary.redact import RedactionFailed, RedactionResult, redact
from bok_core.boundary.sensitivity import Labelled, Sensitivity

KEY = b"test-key; real keys come from BOK_REDACTION_KEY and are never committed"
K1 = b"placeholder-key-one-not-a-secret-000"  # >= 32 bytes, obviously fake
K2 = b"placeholder-key-two-not-a-secret-000"

DOC = (
    "Invoice from ana@example.test, phone 555-010-0100, routing 021000021, "
    "account 12345678. Contact ana@example.test again."
)

_SURROGATE = re.compile(r"\[[A-Z_]+:[a-p]{12}\]")


def _cc(text: str) -> Labelled[str]:
    return Labelled(text, Sensitivity.CLIENT_CONFIDENTIAL)


def _fragments(identifier: str, n: int = 4) -> set[str]:
    return {identifier[i : i + n] for i in range(len(identifier) - n + 1)}


def _leftover(text: str) -> str:
    """The output with every surrogate removed: what is left is what was NOT redacted."""
    return _SURROGATE.sub("\x00", text)


def test_identifiers_are_replaced_by_keyed_stable_surrogates() -> None:
    r = redact(_cc(DOC), key=KEY)
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
    r = redact(_cc(DOC), key=KEY)
    blob = r.model_dump_json() + repr(r) + str(r)
    for identifier in ("ana@example.test", "021000021", "12345678", "555-010-0100"):
        assert identifier not in blob


def test_surrogates_are_keyed_so_a_redacted_document_is_not_a_lookup_table() -> None:
    """R1: a surrogate of sha256(identifier)[:8] is reversible by dictionary attack for
    exactly the classes that matter -- the entire 9-digit routing space enumerates in
    seconds, and so does any phone number."""
    one = redact(_cc("routing 021000021"), key=K1)
    two = redact(_cc("routing 021000021"), key=K2)
    assert one.text != two.text


def test_verification_re_runs_detection_and_catches_what_substitution_missed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R1: THE test the pre-revision plan did not have.

    Verification re-runs every DETECTOR over the output. Here substitution is disabled
    for one class while detection stays on -- simulating a genuine miss.
    """
    import bok_core.boundary.redact as m

    monkeypatch.setitem(m._SUBSTITUTION_DISABLED, "routing", True)
    r = redact(_cc("routing 021000021"), key=KEY)
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
        redact(_cc(DOC), key=b"")


def test_declared_coverage_matches_the_detectors_that_exist() -> None:
    """00 section 4.2 names six identifier classes. Whichever ship, the gap is DECLARED."""
    import bok_core.boundary.redact as m

    assert set(m._DETECTORS) == set(m.COVERED)
    assert set(m.NOT_COVERED) == {"person_name", "address"}
    assert not set(m.COVERED) & set(m.NOT_COVERED)


# --- Beyond the brief -------------------------------------------------------------------


def test_methodology_declares_every_covered_and_uncovered_class() -> None:
    import bok_core.boundary.redact as m

    doc = (Path(__file__).parents[2] / "docs" / "methodology.md").read_text(encoding="utf-8")
    for kind in (*m.COVERED, *m.NOT_COVERED):
        assert f"`{kind}`" in doc, kind


@given(
    kind=st.sampled_from(["email", "phone", "iban", "card", "routing", "tax_id", "account"]),
    original=st.text(min_size=1, max_size=40),
    key=st.binary(min_size=32),
)
def test_a_surrogate_never_looks_like_an_identifier(kind: str, original: str, key: bytes) -> None:
    """A hex digest contains runs of 8-10 decimal digits a few percent of the time, so
    the surrogate alphabet must carry no digits or a CORRECT redaction fails verification."""
    import bok_core.boundary.redact as m

    surrogate = m._surrogate(kind, original, key)
    assert not any(p.search(surrogate) for p in m._DETECTORS.values())


def test_same_key_same_input_same_surrogate() -> None:
    a = redact(_cc("routing 021000021"), key=KEY)
    b = redact(_cc("routing 021000021"), key=KEY)
    assert a.text == b.text
    assert a.surrogate_count == {"routing": 1}


# --- Fix round 1 ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "iban",
    [
        "NL91ABNA0417164300",  # was split by `phone` -> "NL91ABNA[PHONE:..]", verified=True
        "GB82 WEST 1234 5698 7654 32",  # was split by `card`, no spaced shape existed
        "NO93 8601 1117 947",
    ],
)
def test_an_iban_is_redacted_whole_not_split_by_a_digit_detector(iban: str) -> None:
    r = redact(_cc(f"pay to {iban} today"), key=KEY)
    assert r.verified is True
    assert r.surrogate_count == {"iban": 1}
    assert not _fragments(iban) & _fragments(_leftover(r.text))


@pytest.mark.parametrize(
    ("variant", "plain", "kind"),
    [
        ("4111\u00a01111\u00a01111\u00a01111", "4111 1111 1111 1111", "card"),  # NBSP
        ("4111\u202f1111\u20091111\u20021111", "4111 1111 1111 1111", "card"),  # other Zs
        ("4111.1111.1111.1111", "4111.1111.1111.1111", "card"),  # dots
        ("555\u2013010\u20130100", "555-010-0100", "phone"),  # en-dash
        ("555\u2014010\u22120100", "555-010-0100", "phone"),  # em-dash, minus sign
        ("555\u2011010\u20110100", "555-010-0100", "phone"),  # non-breaking hyphen
        ("0210\u200b00021", "021000021", "routing"),  # zero-width space
        ("0210\u00ad000\u206021", "021000021", "routing"),  # soft hyphen, word joiner
        ("\uff10\uff12\uff11000021", "021000021", "routing"),  # full-width digits
    ],
)
def test_unicode_separators_and_format_characters_do_not_defeat_detection(
    variant: str, plain: str, kind: str
) -> None:
    """DOM text is full of NBSP; copy-paste carries en-dashes and zero-width characters.
    Each of these passed through untouched with verified=True before normalisation."""
    r = redact(_cc(f"ref {variant} end"), key=KEY)
    assert r.verified is True
    assert r.surrogate_count == {kind: 1}
    # The surrogate is computed on the NORMALISED identifier, so joins survive the noise.
    assert r.text == redact(_cc(f"ref {plain} end"), key=KEY).text


def test_an_unverified_result_does_not_print_the_identifier_that_survived(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The failed path is the one most likely to reach a log line or a traceback."""
    import bok_core.boundary.redact as m

    monkeypatch.setitem(m._SUBSTITUTION_DISABLED, "routing", True)
    r = redact(_cc("routing 021000021"), key=KEY)
    assert r.verified is False
    assert "021000021" not in repr(r) + str(r) + f"{r}"
    built = RedactionResult(
        text="acct 12345678", verified=False, surrogate_count={}, failures=["account"]
    )
    assert "12345678" not in repr(built) + str(built)


def test_substitution_runs_to_a_fixpoint_before_verification() -> None:
    """Replacing a match can newly satisfy another detector's lookbehind: here the phone
    surrogate's ']' lets '+352305694168' match as a phone that '2+352...' did not."""
    r = redact(_cc("5603699602+352305694168"), key=KEY)
    assert r.verified is True, r.failures
    assert not _fragments("5603699602+352305694168") & _fragments(_leftover(r.text))


def test_digit_runs_longer_than_a_card_are_still_redacted() -> None:
    for run in ("1" * 20, "12345678901234567890123456789", "1234 5678 9012 3456 7890 1234"):
        r = redact(_cc(f"id {run} end"), key=KEY)
        assert r.verified is True
        assert not _fragments(run) & _fragments(_leftover(r.text)), run


_HOSTILE = {
    "word_run": "a" * 200_000,
    "dotted_run": "a." * 100_000,
    "iban_prefix_run": "GB12" * 50_000,
    "digit_run": "1" * 200_000,
    "spaced_digits": "1 " * 100_000,
    "long_upper": "AB12" + "A" * 200_000,
    "at_signs": "a@" * 100_000,
    "paren_groups": "(123)" * 40_000,
}


@pytest.mark.parametrize("name", sorted(_HOSTILE))  # ids, not 200k-char values: Windows
def test_hostile_input_is_redacted_in_linear_time(name: str) -> None:  # caps env vars
    """Every detector is length-bounded or unambiguous, so no input backtracks
    quadratically. 'GB12' * 50_000 also used to fail closed (matched only at its end)."""
    hostile = _HOSTILE[name]
    started = time.perf_counter()
    r = redact(_cc(hostile), key=KEY)
    assert time.perf_counter() - started < 5.0
    assert r.verified is True


def test_a_short_key_is_refused_without_echoing_it() -> None:
    weak = b"SECRETKEY-31-bytes-long-xxxxxxx"
    assert len(weak) == 31
    with pytest.raises(ValueError, match="at least 32 bytes") as excinfo:
        redact(_cc(DOC), key=weak)
    assert "SECRETKEY" not in str(excinfo.value)
    redact(_cc(DOC), key=weak + b"x")  # exactly 32 is accepted


# --- Properties -------------------------------------------------------------------------

_SEP = st.sampled_from([" ", "-", ".", ""])


@st.composite
def _phone(draw: st.DrawFn) -> str:
    sep = draw(_SEP)
    area = draw(st.from_regex(r"[0-9]{3}", fullmatch=True))
    area = f"({area})" if draw(st.booleans()) else area
    cc = draw(st.sampled_from(["", "+1 ", "+44-", "+353"]))
    a = draw(st.from_regex(r"[0-9]{3}", fullmatch=True))
    b = draw(st.from_regex(r"[0-9]{4}", fullmatch=True))
    return f"{cc}{area}{draw(_SEP) if area[0] == '(' else sep}{a}{sep}{b}"


@st.composite
def _card(draw: st.DrawFn) -> str:
    groups = [draw(st.from_regex(r"[0-9]{4}", fullmatch=True)) for _ in range(4)]
    return "".join(g + draw(_SEP) for g in groups[:-1]) + groups[-1]


_TAGGED = st.one_of(
    st.tuples(st.just("email"), st.from_regex(r"[a-z]{1,8}@[a-z]{1,8}\.test", fullmatch=True)),
    st.tuples(st.just("phone"), _phone()),
    st.tuples(st.just("iban"), st.from_regex(r"GB[0-9]{2}[A-Z0-9]{14}", fullmatch=True)),
    st.tuples(
        st.just("iban"), st.from_regex(r"GB[0-9]{2}( [A-Z0-9]{4}){4} [0-9]{2}", fullmatch=True)
    ),
    st.tuples(st.just("card"), _card()),
    st.tuples(st.just("routing"), st.from_regex(r"[0-9]{9}", fullmatch=True)),
    st.tuples(st.just("tax_id"), st.from_regex(r"[0-9]{2}-[0-9]{7}", fullmatch=True)),
    st.tuples(st.just("tax_id"), st.from_regex(r"[0-9]{3}-[0-9]{2}-[0-9]{4}", fullmatch=True)),
    st.tuples(st.just("account"), st.from_regex(r"[0-9]{8}", fullmatch=True)),
)


@st.composite
def _noisy(draw: st.DrawFn, tagged: tuple[str, str]) -> tuple[str, str]:
    """Swap ASCII separators for Unicode look-alikes, sprinkle format characters between
    digits, and sometimes widen digits -- what DOM text and copy-paste actually carry."""
    kind, value = tagged
    out: list[str] = []
    for ch in value:
        if ch == " ":
            out.append(draw(st.sampled_from([" ", "\u00a0", "\u202f", "\u2009"])))
        elif ch == "-":
            out.append(draw(st.sampled_from(["-", "\u2013", "\u2014", "\u2212", "\u2011"])))
        elif ch.isdigit() and draw(st.integers(0, 7)) == 0:
            out.append(chr(ord(ch) - 0x30 + 0xFF10))
        else:
            out.append(ch)
        if ch.isdigit():
            out.append(draw(st.sampled_from(["", "", "", "", "\u200b", "\u00ad", "\u2060"])))
    return kind, "".join(out)


def _assert_redacted(doc: str, tagged: list[tuple[str, str]], *, exact_kinds: bool) -> None:
    import bok_core.boundary.redact as m

    r = redact(_cc(doc), key=KEY)
    assert r.verified is True, r.failures
    left = _leftover(r.text)
    for _, value in tagged:
        normal = m._normalise(value)
        assert not _fragments(normal) & _fragments(left), (normal, r.text)
    if exact_kinds:
        expected = Counter(kind for kind, _ in {(k, m._normalise(v)) for k, v in tagged})
        assert r.surrogate_count == dict(expected)


@given(tagged=st.lists(_TAGGED.flatmap(_noisy), min_size=1, max_size=6))
def test_separated_identifiers_are_each_redacted_whole_and_classified(
    tagged: list[tuple[str, str]],
) -> None:
    """Per-kind counts catch a split or a misclassification that a bare 'verified' and
    'original absent' assertion cannot see: NL91ABNA[PHONE:..] passed both."""
    doc = "<< " + " and ".join(v for _, v in tagged) + " >>"
    _assert_redacted(doc, tagged, exact_kinds=True)


@given(
    tagged=st.lists(_TAGGED.flatmap(_noisy), min_size=2, max_size=6),
    joiners=st.lists(
        st.sampled_from(["", "", " ", ",", ", ", ";", "/", ":", "|", "(", ")", "."]),
        min_size=5,
        max_size=5,
    ),
)
def test_adjacent_identifiers_leave_no_fragment(
    tagged: list[tuple[str, str]], joiners: list[str]
) -> None:
    """Adjacent -- including GLUED, with no separator at all -- identifiers may
    legitimately merge (two digit runs separated by one space ARE one longer run), so
    classification is not asserted -- only that no 4-character fragment survives.

    Each of these was a verified=True leak found by this property before the span-merge
    rewrite: "a@a.test.GB00..", "000 000 0000+44-..", "(000) 000 000000000000",
    "..AAAA000000000GB00 ZDPK ..", "..GB00 0AAA AAAA 00000000000"."""
    doc = "<<" + tagged[0][1]
    for (_, value), joiner in zip(tagged[1:], joiners, strict=False):
        doc += joiner + value
    _assert_redacted(doc + ">>", tagged, exact_kinds=False)
