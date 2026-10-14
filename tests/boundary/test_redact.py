import re
import time
import unicodedata
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


# --- Fix round 2 ------------------------------------------------------------------------


@pytest.mark.parametrize("phone", ["555 010-0100", "555.010-0100", "555-010 0100", "555/010.0100"])
def test_a_phone_with_mixed_separators_is_redacted(phone: str) -> None:
    """Round 1's backreference demanded matching separators: these passed unchanged."""
    r = redact(_cc(f"phone {phone} end"), key=KEY)
    assert r.verified is True
    assert r.surrogate_count == {"phone": 1}
    assert not _fragments(phone) & _fragments(_leftover(r.text))


@pytest.mark.parametrize(
    ("variant", "kind"),
    [
        ("4111  1111 1111 1111", "card"),  # double space
        ("4111\t1111\t1111\t1111", "card"),  # innerText of a table row
        ("4111\n1111\n1111\n1111", "card"),  # one group per line
        ("4111 - 1111 - 1111 - 1111", "card"),
        ("4111/1111/1111/1111", "card"),
        ("4111 \t1111\r\n1111.-1111", "card"),
        ("1234 5678 9012", "account"),  # 12 spaced digits matched no detector
        ("1234\t5678", "account"),
    ],
)
def test_digit_groups_split_by_wider_separators_are_redacted(variant: str, kind: str) -> None:
    r = redact(_cc(f"ref {variant} end"), key=KEY)
    assert r.verified is True
    assert r.surrogate_count == {kind: 1}
    for group in re.split(r"\D+", variant):
        assert group not in _leftover(r.text).replace("ref", "").replace("end", "")


@pytest.mark.parametrize(
    "invisible",
    [
        "\u034f",  # combining grapheme joiner (Mn, default-ignorable)
        "\ufe0f",  # variation selector-16 (Mn, default-ignorable)
        "\U000e0101",  # variation selector-18 (Mn, default-ignorable)
        "\u2800",  # braille pattern blank (So)
        "\u3164",  # hangul filler (Lo; NFKC -> U+1160)
        "\u1160",  # hangul jungseong filler (Lo, default-ignorable)
        "\u115f",  # hangul choseong filler (Lo, default-ignorable)
        "\uffa0",  # halfwidth hangul filler (Lo, default-ignorable)
        "\u17b4",  # khmer vowel inherent aq (Mn, default-ignorable)
        "\u180e",  # mongolian vowel separator (Cf)
        "\U000e0041",  # tag latin capital A (Cf, default-ignorable)
        "\U0001d173",  # musical symbol begin beam (Cf, default-ignorable)
        "\u0301",  # combining acute accent (Mn) between digits
        "\u0301\u0302",  # a stack of combining marks
    ],
)
def test_invisible_characters_between_digits_do_not_defeat_detection(invisible: str) -> None:
    plain = redact(_cc("routing 021000021 end"), key=KEY)
    r = redact(_cc(f"routing 021{invisible}000{invisible}021 end"), key=KEY)
    assert r.verified is True
    assert r.surrogate_count == {"routing": 1}
    assert r.text == plain.text


@pytest.mark.parametrize(
    ("one", "two"),
    [
        ("GB82 WEST 1234 5698 7654 32", "GB82WEST12345698765432"),
        ("gb82 west 1234 5698 7654 32", "GB82WEST12345698765432"),
        ("555-010-0100", "(555) 010 0100"),
        ("555-010-0100", "555.010.0100"),
        ("4111 1111 1111 1111", "4111111111111111"),
        ("ana@x.test", "ANA@X.TEST"),
    ],
)
def test_one_identifier_shares_a_surrogate_across_layouts_and_case(one: str, two: str) -> None:
    """Joins survive layout: the HMAC input is the canonical identifier, not the text."""
    a = redact(_cc(f"<{one}>"), key=KEY)
    b = redact(_cc(f"<{two}>"), key=KEY)
    assert a.verified and b.verified
    assert a.text == b.text


# --- Fix round 3 ------------------------------------------------------------------------

_KEPT_CONTROLS = "\t\n\r\x0b\x0c"
_PLAIN_ROUTING = "routing 021000021 end"


@pytest.mark.parametrize(
    "cp", [cp for cp in (*range(0x00, 0x20), *range(0x7F, 0xA0)) if chr(cp) not in _KEPT_CONTROLS]
)
def test_every_control_character_between_digits_is_stripped(cp: int) -> None:
    """All of C0/C1 (DEL and NEL included) except the five whitespace controls: each one
    split '021000021' invisibly and passed with verified=True."""
    c = chr(cp)
    r = redact(_cc(f"routing 021{c}000{c}021 end"), key=KEY)
    assert r.verified is True
    assert r.text == redact(_cc(_PLAIN_ROUTING), key=KEY).text


def _all_digit_zeros() -> list[int]:
    """The zero of every decimal-digit script Python knows (Nd with value 0)."""
    return [
        cp
        for cp in range(0x110000)
        if unicodedata.category(chr(cp)) == "Nd" and unicodedata.decimal(chr(cp)) == 0
    ]


def test_every_decimal_digit_script_is_redacted_even_with_marks_after_digits() -> None:
    """All Nd digits fold to ASCII, and a combining mark after any of them is stripped:
    Arabic-Indic '021' + U+0301 + '000' ... and its 650-digit siblings leaked."""
    plain = redact(_cc(_PLAIN_ROUTING), key=KEY).text
    zeros = _all_digit_zeros()
    assert len(zeros) >= 60
    for zero in zeros:
        digits = [chr(zero + d) for d in (0, 2, 1, 0, 0, 0, 0, 2, 1)]
        bare = "".join(digits)
        marked = "".join(d + "\u0301" for d in digits)
        for variant in (bare, marked):
            r = redact(_cc(f"routing {variant} end"), key=KEY)
            assert r.verified is True, hex(zero)
            assert r.text == plain, hex(zero)


@pytest.mark.parametrize(
    "variant",
    [
        "021\u2003\u0301000\u2003\u0301021",  # mark after non-ASCII whitespace
        "021 \u0301000 \u0301021",  # mark after ASCII space
        "021\x0b\u0301000\x0b\u0301021",  # mark after vertical tab
        "\u0662\u0660\u0661\u0301\u0660\u0660\u0660\u0301\u0660\u0662\u0661",
        "\u0966\u0968\u0967\u093c\u0966\u0966\u0966\u093c\u0966\u0968\u0967",
    ],
)
def test_marks_after_any_digit_or_gap_are_stripped(variant: str) -> None:
    r = redact(_cc(f"ref {variant} end"), key=KEY)
    assert r.verified is True
    assert sum(r.surrogate_count.values()) == 1
    assert not re.search(r"\d", _leftover(r.text))


@pytest.mark.parametrize(
    "layout",
    [
        "GB82-WEST-1234-5698-7654-32",  # was "GB82-WEST-[CARD]"
        "GB82.WEST.1234.5698.7654.32",
        "GB82/WEST/1234/5698/7654/32",
        "GB82\tWEST\t1234\t5698\t7654\t32",
        "GB82  WEST  1234  5698  7654  32",
        "gb82-west-1234-5698-7654-32",
        "GB82WEST 1234 5698 7654 32",
        "GB82 - WEST - 1234 - 5698 - 7654 - 32",
    ],
)
def test_an_iban_in_any_covered_layout_is_one_iban(layout: str) -> None:
    # ";" after the IBAN: a following 1-4 character word may be absorbed (declared, see
    # test_an_iban_followed_by_a_short_word_loses_its_join_but_never_leaks).
    compact = redact(_cc("pay GB82WEST12345698765432; now"), key=KEY)
    r = redact(_cc(f"pay {layout}; now"), key=KEY)
    assert r.verified is True
    assert r.surrogate_count == {"iban": 1}
    assert r.text == compact.text  # one surrogate across layouts and case


def test_an_iban_with_letters_in_its_trailing_groups_leaves_nothing() -> None:
    """'MTLC  AST0  01S' survived when only single spaces joined groups."""
    iban = "MT84  MALT  0110  0001  2345  MTLC  AST0  01S"
    r = redact(_cc(f"pay {iban} now"), key=KEY)
    assert r.verified is True
    assert r.surrogate_count == {"iban": 1}
    assert not _fragments(iban) & _fragments(_leftover(r.text))
    for group in ("MTLC", "AST0", "01S"):
        assert group not in r.text


@pytest.mark.parametrize(
    "email", ["ana@\u0301x.test", "ana@x\u0301.test", "ana@x.t\u0301est", "a\u20ddna@x.test"]
)
def test_combining_marks_inside_an_email_do_not_defeat_detection(email: str) -> None:
    plain = redact(_cc("mail ana@x.test now"), key=KEY)
    r = redact(_cc(f"mail {email} now"), key=KEY)
    assert r.verified is True
    assert r.text == plain.text


def test_an_iban_absorbs_a_short_following_word_and_redacts_it() -> None:
    """Declared over-redaction: the trailing group of an IBAN may be letters (Seychelles
    ends in 'USD', Malta in '01S'), so a 1-4 character word after an IBAN is taken too.
    Safe for the boundary; the cost is a different surrogate in that context."""
    r = redact(_cc("SC52 BAHL 0103 1234 5678 9012 3456 USD and more"), key=KEY)
    assert r.verified is True
    assert "USD" not in r.text
    assert "BAHL" not in r.text
    assert r.text.endswith(" more")


def test_an_iban_followed_by_a_short_word_loses_its_join_but_never_leaks() -> None:
    """Declared trade-off. The overlapping IBAN scan (needed for IBANs glued at another
    4-alignment) finds 'ST12345698765432 now' inside 'GB82WEST12345698765432 now'; the
    span widens to a merged span, keyed on its full text. The word is redacted, the IBAN
    is redacted, and the surrogate differs from the IBAN's standalone one."""
    standalone = redact(_cc("GB82WEST12345698765432;"), key=KEY)
    absorbed = redact(_cc("GB82WEST12345698765432 now;"), key=KEY)
    assert absorbed.verified is True
    assert absorbed.surrogate_count == {"iban": 1}
    assert "now" not in absorbed.text
    assert absorbed.text != standalone.text


def test_a_merged_span_does_not_share_the_standalone_identifiers_surrogate() -> None:
    """'4111 1111 1111 1111a@b.cc' merged into one span labelled card; its canonical form
    kept only the digits, so it got the standalone card's surrogate -- a false join."""
    standalone = redact(_cc("4111 1111 1111 1111"), key=KEY)
    merged = redact(_cc("4111 1111 1111 1111a@b.cc"), key=KEY)
    assert merged.verified is True
    assert "a@b.cc" not in merged.text
    assert merged.text != standalone.text


# --- Properties -------------------------------------------------------------------------

_SEP = st.sampled_from([" ", "-", ".", "", "\t", "\n", "  ", " - ", "/", "\r\n"])


@st.composite
def _phone(draw: st.DrawFn) -> str:
    area = draw(st.from_regex(r"[0-9]{3}", fullmatch=True))
    area = f"({area})" if draw(st.booleans()) else area
    cc = draw(st.sampled_from(["", "+1 ", "+44-", "+353"]))
    a = draw(st.from_regex(r"[0-9]{3}", fullmatch=True))
    b = draw(st.from_regex(r"[0-9]{4}", fullmatch=True))
    return f"{cc}{area}{draw(_SEP)}{a}{draw(_SEP)}{b}"  # separators independent


@st.composite
def _card(draw: st.DrawFn) -> str:
    groups = [draw(st.from_regex(r"[0-9]{4}", fullmatch=True)) for _ in range(4)]
    return "".join(g + draw(_SEP) for g in groups[:-1]) + groups[-1]


_IBAN_GAP = st.sampled_from([" ", "", "-", ".", "/", "\t", "  ", " - ", "\n"])


@st.composite
def _iban(draw: st.DrawFn) -> str:
    """Every covered layout: compact, or groups of four joined by any covered gap (the
    gaps independent), either case, with a trailing group of 1-4 that may hold letters."""
    groups = [draw(st.from_regex(r"[A-Za-z0-9]{4}", fullmatch=True)) for _ in range(4)]
    tail = draw(st.from_regex(r"[A-Za-z0-9]{1,4}", fullmatch=True))
    cc = draw(st.sampled_from(["GB", "gb", "MT", "Nl"]))
    check = draw(st.from_regex(r"[0-9]{2}", fullmatch=True))
    body = "".join(draw(_IBAN_GAP) + g for g in [*groups, tail])
    return f"{cc}{check}{body}"


_TAGGED = st.one_of(
    st.tuples(st.just("email"), st.from_regex(r"[a-z]{1,8}@[a-z]{1,8}\.test", fullmatch=True)),
    st.tuples(st.just("phone"), _phone()),
    st.tuples(st.just("iban"), st.from_regex(r"GB[0-9]{2}[A-Z0-9]{14}", fullmatch=True)),
    st.tuples(
        st.just("iban"), st.from_regex(r"GB[0-9]{2}( [A-Z0-9]{4}){4} [0-9]{2}", fullmatch=True)
    ),
    st.tuples(st.just("iban"), _iban()),
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
    zero = draw(st.sampled_from(_DIGIT_ZEROS))  # one script per identifier, sometimes
    out: list[str] = []
    for ch in value:
        if ch == " ":
            out.append(draw(st.sampled_from([" ", "\u00a0", "\u202f", "\u2009"])))
        elif ch == "-":
            out.append(draw(st.sampled_from(["-", "\u2013", "\u2014", "\u2212", "\u2011"])))
        elif ch.isdigit() and draw(st.integers(0, 3)) == 0:
            out.append(chr(zero + int(ch)))
        else:
            out.append(ch)
        if ch.isdigit():
            out.append(draw(st.sampled_from(_BETWEEN_DIGITS)))
        elif kind == "email" and draw(st.integers(0, 5)) == 0:
            out.append(draw(st.sampled_from(["\u0301", "\u0308", "\u20dd", "\u200d"])))
    return kind, "".join(out)


_DIGIT_ZEROS = [
    0x0030,  # ASCII
    0xFF10,  # full-width
    0x0660,  # Arabic-Indic
    0x06F0,  # extended Arabic-Indic
    0x0966,  # Devanagari
    0x09E6,  # Bengali
    0x0E50,  # Thai
    0x1040,  # Myanmar
    0x1D7CE,  # mathematical bold
    0x1E950,  # Adlam
]


_BETWEEN_DIGITS = [
    *[""] * 8,
    "\u200b",  # zero-width space (Cf)
    "\u00ad",  # soft hyphen (Cf)
    "\u2060",  # word joiner (Cf)
    "\u034f",  # combining grapheme joiner (Mn, default-ignorable)
    "\ufe0f",  # variation selector-16
    "\u2800",  # braille pattern blank
    "\u3164",  # hangul filler
    "\uffa0",  # halfwidth hangul filler
    "\u0301",  # combining acute accent
    "\u093c",  # devanagari nukta (Mn) -- after a non-ASCII digit too
    "\u20e3",  # combining enclosing keycap (Me)
    "\U000e0041",  # tag character
    "\x00",  # C0 controls
    "\x08",
    "\x1b",
    "\x7f",  # DEL
    "\x85",  # NEL (C1)
    "\x9f",  # C1
]


def _assert_redacted(doc: str, tagged: list[tuple[str, str]], *, exact_kinds: bool) -> None:
    import bok_core.boundary.redact as m

    r = redact(_cc(doc), key=KEY)
    assert r.verified is True, r.failures
    left = _leftover(r.text)
    for _, value in tagged:
        normal = m._normalise(value)
        assert not _fragments(normal) & _fragments(left), (normal, r.text)
    if exact_kinds:
        canonical = {(k, m._canonical(k, m._normalise(v))) for k, v in tagged}
        expected = Counter(kind for kind, _ in canonical)
        assert r.surrogate_count == dict(expected)


@given(tagged=st.lists(_TAGGED.flatmap(_noisy), min_size=1, max_size=6))
def test_separated_identifiers_are_each_redacted_whole_and_classified(
    tagged: list[tuple[str, str]],
) -> None:
    """Per-kind counts catch a split or a misclassification that a bare 'verified' and
    'original absent' assertion cannot see: NL91ABNA[PHONE:..] passed both.

    The joiner is " ; " because an IBAN absorbs a following word of 1-4 letters/digits
    (its trailing group may be letters), and absorbing " and" widens the span into a
    merged span with its own surrogate -- declared, and pinned separately by
    test_an_iban_absorbs_a_short_following_word_and_redacts_it."""
    doc = "<< " + " ; ".join(v for _, v in tagged) + " >>"
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
