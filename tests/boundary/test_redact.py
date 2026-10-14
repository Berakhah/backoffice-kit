import gc
import json
import re
import time
import unicodedata
from collections import Counter
from pathlib import Path

import pytest
from hypothesis import given, settings
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


# Repeating units, each tiled to a target length. The test ids are the names, never the
# values: Windows caps the env var in which pytest stores the current test id.
_HOSTILE = {
    "word_run": "a",
    "dotted_run": "a.",
    "iban_prefix_run": "GB12",
    "digit_run": "1",
    "spaced_digits": "1 ",
    "long_upper": "A",
    "at_signs": "a@",
    "paren_groups": "(123)",
    "double_quotes": '"',
    "open_parens": "(",
    "apostrophes": "a'",
    "atext_run": "!#$%&'*+/=?^_`{|}~-",
    "iban_national_run": "GB 82 ",
    "quote_letter": '"a',
    "quoted_letter_at": '"a"@',
    "escaped_quotes": '"\\"',
    "nested_comment": "((a)",
    "comment_at": "(a)@",
    "quoted_at_62": '"' + "a" * 62 + '@"',
    "domain_literal": "a@[",
    "local_64_then_dots": "a" * 64 + "@" + "a." * 120,
    "ab12_words": "ab12 ",
    "gapped_lower_cc": "gb 82 ",
    "upper_gapped": "AA 00 ",
    "html": '<td class="x-1 y_2">Ab12 cd34 @ ef.gh</td> ',
    "quoted_comment_chain": '"a"(b)' * 10 + "@ ",
    "json_escaped": '{\\"to\\":\\"jo smith\\"@x.test\\"} ',
    "at_runs": "@@@@4111 ",
}


def _tile(unit: str, n: int) -> str:
    return (unit * (n // len(unit) + 1))[:n]


def _best_time(text: str, runs: int) -> float:
    """The fastest of `runs` timings, with the garbage collector off while timing: a
    collection (its cost grows with the heap, not the input) landing inside one run is
    noise, and so is a burst of CPU contention. Noise only ever INFLATES a timing, so the
    minimum is the cleanest estimate of the real cost."""
    best = float("inf")
    for _ in range(runs):
        gc.collect()
        gc.disable()
        try:
            started = time.perf_counter()
            redact(_cc(text), key=KEY)
            best = min(best, time.perf_counter() - started)
        finally:
            gc.enable()
    return best


_SCALING_BOUND = 20  # 10x the input; linear is ~10x, quadratic ~100x
_SCALING_ATTEMPTS = 3


@pytest.mark.parametrize("name", sorted(_HOSTILE))
def test_hostile_input_scales_linearly(name: str) -> None:
    """10x the input must cost well under 20x the time. This is a ratio, not an absolute
    bound: the redactor runs on whole DOM snapshots, so a super-linear regression must
    fail here, but a slow CI machine must not. A run under 50 ms at 100k is not judged.

    Stabilised (it failed 2 of 4 full-suite runs under coverage and machine load: one
    unlucky 100k run): a warm-up, best-of timings, and up to 3 measurement rounds, each
    taking the minimum over ALL rounds so far for BOTH sizes. Taking minima on both sides
    cannot hide super-linear growth -- a quadratic scan is ~100x at every round -- it only
    discards rounds that noise inflated."""
    small_text = _tile(_HOSTILE[name], 10_000)
    large_text = _tile(_HOSTILE[name], 100_000)
    redact(_cc(small_text), key=KEY)  # warm-up: regex compilation caches, allocator
    small = large = float("inf")
    for _ in range(_SCALING_ATTEMPTS):
        small = min(small, _best_time(small_text, runs=3))
        large = min(large, _best_time(large_text, runs=1))
        if large < 0.05 or large < _SCALING_BOUND * max(small, 0.0025):
            return
    pytest.fail(f"super-linear: {name} 10k {small:.4f}s, 100k {large:.4f}s")


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
    r = redact(_cc("SC52 BAHL 0103 1234 5678 9012 3456 USD and more; end"), key=KEY)
    assert r.verified is True
    assert "USD" not in r.text
    assert "BAHL" not in r.text
    # Task 8b: the national-layout fallback absorbs words up to 30 letters/digits, here
    # through an inner match ("HL 0103 ..."), so "and more" goes too. Declared.
    assert r.text.endswith("; end")


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


# --- Task 8b: hardening -----------------------------------------------------------------


def _only_surrogate_left(r: RedactionResult, before: str, after: str) -> bool:
    """The identifier is gone WHOLE: nothing but one surrogate between the context words."""
    return _leftover(r.text) == f"{before}\x00{after}"


@pytest.mark.parametrize(
    ("layout", "compact"),
    [
        # national display formats, not groups of four
        ("MT84 MALT 01100 0012345MTLCAST001S", "MT84MALT011000012345MTLCAST001S"),
        ("IT60 X 05428 11101 000000123456", "IT60X0542811101000000123456"),
        ("FR76 30006 00001 12345678901 89", "FR7630006000011234567890189"),
        ("BE68 539 0075470 34", "BE68539007547034"),
        ("PT50 0002 0123 12345678901 54", "PT50000201231234567890154"),
        ("CH93 00762 01162 38529 57", "CH9300762011623852957"),
        ("NO93 8601 1117947", "NO9386011117947"),
        ("SC18 SSCB 1101 0000 0000 0000 1497 USD", "SC18SSCB11010000000000001497USD"),
        # the country code split from its check digits, groups of other widths
        ("GB 82 WEST 1234 5698 7654 32", "GB82WEST12345698765432"),
        ("GB82 WEST12 3456 98 7654 32", "GB82WEST12345698765432"),
        ("GB 82 west12 3456-98.7654/32", "GB82WEST12345698765432"),
        ("gb82 west12 3456-98.7654/32", "GB82WEST12345698765432"),
    ],
)
def test_an_iban_in_a_national_layout_is_redacted_whole(layout: str, compact: str) -> None:
    """'IT60 X [DIGIT_RUN]', '[IBAN]MTLCAST001S', 'GB 82 WEST [CARD]' and 'GB82 WE[IBAN]'
    all verified=True with a prefix or tail of the IBAN left in the text."""
    r = redact(_cc(f"pay {layout}; now"), key=KEY)
    assert r.verified is True
    assert r.surrogate_count == {"iban": 1}
    assert _only_surrogate_left(r, "pay ", "; now"), r.text
    assert r.text == redact(_cc(f"pay {compact}; now"), key=KEY).text  # joins survive


@pytest.mark.parametrize(
    "email",
    [
        "jane.o'connor@corp.test",  # was "jane.o'[EMAIL]"
        "first&last@corp.test",
        "a!b#c$d%e&f'g*h+i/j=k?l^m_n`o{p|q}r~s@x.test",
        '"john smith"@x.test',
        "ana(comment)@x.test",
        "(comment)ana@x.test",
        # EAI: Devanagari local part (vowel signs are Mc, outside \w)
        "\u092a\u094d\u0930\u093f\u092f\u093e.\u0936\u0930\u094d\u092e\u093e@x.test",
    ],
)
def test_an_email_with_a_full_rfc5322_local_part_is_redacted_whole(email: str) -> None:
    r = redact(_cc(f"mail {email} now"), key=KEY)
    assert r.verified is True
    assert r.surrogate_count == {"email": 1}
    assert _only_surrogate_left(r, "mail ", " now"), r.text


@pytest.mark.parametrize(
    ("separator", "maps_to"),
    [
        ("\u2044", "/"),  # fraction slash
        ("\u2215", "/"),  # division slash
        ("\u29f8", "/"),  # big solidus
        ("\uff0f", "/"),  # full-width solidus (NFKD)
        ("\u2571", "/"),  # box drawings diagonal
        ("\u3002", "."),  # ideographic full stop
        ("\uff61", "."),  # halfwidth ideographic full stop
        ("\uff0e", "."),  # full-width full stop (NFKD)
        ("\u06d4", "."),  # arabic full stop
        ("\u00b7", "."),  # middle dot
        ("\u2022", "."),  # bullet
        ("\u30fb", "."),  # katakana middle dot
        ("\u30fc", "-"),  # katakana prolonged sound mark
        ("\uff70", "-"),  # halfwidth prolonged sound mark
        ("\u2500", "-"),  # box drawings light horizontal
        ("\u2501", "-"),  # box drawings heavy horizontal
        ("\u2550", "-"),  # box drawings double horizontal
        ("\u2796", "-"),  # heavy minus sign
        ("\u02d7", "-"),  # modifier letter minus sign
        ("\u2043", "-"),  # hyphen bullet
        ("\u23af", "-"),  # horizontal line extension
    ],
)
def test_lookalike_separators_are_mapped_into_the_gap_set(separator: str, maps_to: str) -> None:
    import bok_core.boundary.redact as m

    assert m._normalise(separator) == maps_to
    r = redact(_cc("card " + separator.join(["4111"] * 4) + "; now"), key=KEY)
    assert r.verified is True
    assert r.surrogate_count == {"card": 1}
    assert _only_surrogate_left(r, "card ", "; now"), r.text


@pytest.mark.parametrize(
    "junk",
    [
        chr(0xD800),  # lone high surrogate (JS strings reach Python via JSON this way)
        chr(0xDFFF),  # lone low surrogate
        "\ue000",  # private use (Co)
        "\U000f0000",  # supplementary private use plane A
        "\U00100000",  # supplementary private use plane B
        "\u0378",  # unassigned (Cn)
    ],
)
def test_surrogates_private_use_and_unassigned_code_points_are_stripped(junk: str) -> None:
    r = redact(_cc(f"card 4111{junk} 1111{junk}1111 1111{junk}; now"), key=KEY)
    assert r.verified is True
    assert r.surrogate_count == {"card": 1}
    assert _only_surrogate_left(r, "card ", "; now"), r.text
    # The result is always serialisable: no lone surrogate survives into the output.
    r.text.encode("utf-8")
    assert r.model_dump_json()
    assert json.loads(json.dumps(r.model_dump(), ensure_ascii=False))


def test_a_lone_surrogate_anywhere_never_reaches_the_output() -> None:
    r = redact(_cc("note " + chr(0xD83D) + " end " + chr(0xDE00)), key=KEY)
    r.text.encode("utf-8")
    assert r.text == "note  end "


@pytest.mark.parametrize(
    "variant",
    [
        "ana@x.t\u00e9st",  # precomposed e-acute: NFKC keeps it, the [A-Za-z] TLD fails
        "ana@x.te\u0301st",  # decomposed: NFKC would compose it into the same e-acute
        "\u00e1na@x.test",
    ],
)
def test_a_precomposing_mark_in_an_email_is_pinned(variant: str) -> None:
    """Pins NFKD-then-strip. Under NFKC-then-strip, 'e' + U+0301 composes to U+00E9 (Ll),
    survives the Mn strip, and the email leaks with verified=True."""
    import bok_core.boundary.redact as m

    assert m._normalise(variant) == "ana@x.test"
    plain = redact(_cc("mail ana@x.test now"), key=KEY)
    assert redact(_cc(f"mail {variant} now"), key=KEY).text == plain.text


@pytest.mark.parametrize(
    "variant",
    [
        "GB82 W\u00c9ST 1234 5698 7654 32",  # precomposed E-acute in a BBAN letter
        "GB82 WE\u0301ST 1234 5698 7654 32",  # E + combining acute
        "G\u0302B82 WEST 1234 5698 7654 32",  # mark on the country code
    ],
)
def test_combining_marks_on_iban_letters_do_not_defeat_detection(variant: str) -> None:
    r = redact(_cc(f"pay {variant}; now"), key=KEY)
    assert r.verified is True
    assert r.text == redact(_cc("pay GB82WEST12345698765432; now"), key=KEY).text


def _declared_gaps(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    start = text.index("<!-- declared-gaps:start -->")
    end = text.index("<!-- declared-gaps:end -->")
    return [line.strip() for line in text[start:end].splitlines()[1:] if line.strip()]


def test_declared_gaps_match_between_methodology_and_contract() -> None:
    """The contract's declared-gaps list and methodology.md's must be the same list."""
    docs = Path(__file__).parents[2] / "docs"
    in_methodology = _declared_gaps(docs / "methodology.md")
    in_contract = _declared_gaps(docs / "INTERFACE-CONTRACT.md")
    assert in_methodology == in_contract
    joined = " ".join(in_methodology)
    for named in (
        "U+2776",
        "Ethiopic",
        "Kharoshthi",
        "Brahmi",
        "Rumi",
        "IDN",
        "U+249C",
        "64 characters",
        "ONE layer of JSON string escaping",
        "MUST redact string values BEFORE serialising",
        "HTML entities",
        "percent-encoding",
        "WITHOUT an inner escaped quote",
    ):
        assert named in joined, named


# --- Task 8b fix round 1 ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("layout", "compact"),
    [
        ("gb 82 west 1234 5698 7654 32", "GB82WEST12345698765432"),  # was "gb 82 west [CARD]"
        ("Gb 82 WEST 1234 5698 7654 32", "GB82WEST12345698765432"),  # was "Gb 82 WE[IBAN]"
        ("gB 82 west 1234 5698 7654 32", "GB82WEST12345698765432"),
        ("gb 82 west12 3456 9876 5432", "GB82WEST12345698765432"),
        ("it 60 x 05428 11101 000000123456", "IT60X0542811101000000123456"),
        ("no 93 8601 1117 947", "NO9386011117947"),
        ("be 68 539 0075 4703", "BE6853900754703"),
        ("mt 84 malt 01100 0012345mtlcast001s", "MT84MALT011000012345MTLCAST001S"),
        ("de 89 3704 0044 0532 0130 00", "DE89370400440532013000"),
        ("nl 91 abna 0417 1643 00", "NL91ABNA0417164300"),
        ("nl 91 abna 0417164300", "NL91ABNA0417164300"),
    ],
)
def test_a_gapped_country_code_of_any_case_with_a_digit_heavy_bban_is_an_iban(
    layout: str, compact: str
) -> None:
    r = redact(_cc(f"pay {layout}; now"), key=KEY)
    assert r.verified is True
    assert r.surrogate_count == {"iban": 1}
    assert _only_surrogate_left(r, "pay ", "; now"), r.text
    assert r.text == redact(_cc(f"pay {compact}; now"), key=KEY).text


@pytest.mark.parametrize(
    "prose",
    [
        "on 12 March 2026 we left early",
        "Go 12 rounds then rest a while",
        "in 20 minutes we left the building",
        "up 15 percent on the quarter again",
    ],
)
def test_gapped_lower_case_prose_with_few_digits_is_left_alone(prose: str) -> None:
    """The other direction: a lower/mixed-case gapped 'country code' needs >= 8 digits in
    the 11-30 letters/digits that follow, so ordinary prose is not an IBAN."""
    r = redact(_cc(prose), key=KEY)
    assert r.text == prose


@pytest.mark.parametrize(
    "email",
    [
        '"john\\"smith"@x.test',  # quoted-pair; was '"john\\[EMAIL]'
        '"jonathan.\\"q\\".smith"@x.test',
        "jonathan(a(b)c)@x.test",  # nested comment; was 'jonathan(a(b)c)[EMAIL]'
        "jonathan(comment with (nest))@x.test",
        "jonathan@[192.168.0.1]",  # domain literal; was 'jonathan@[[ACCOUNT]]'
        "jonathan@[IPv6:2001:db8::1]",  # was untouched
        '"john smith"(c)@x.test',
    ],
)
def test_quoted_pairs_nested_comments_and_domain_literals_are_redacted_whole(
    email: str,
) -> None:
    r = redact(_cc(f"mail {email} now"), key=KEY)
    assert r.verified is True
    assert r.surrogate_count == {"email": 1}
    assert _only_surrogate_left(r, "mail ", " now"), r.text


# --- Task 8b fix round 2 ----------------------------------------------------------------


@pytest.mark.parametrize(
    "email",
    [
        '"john smith@acme"@x.test',  # inner "@" after a space cut off the real address
        "jonathan(home x@y)@x.test",
        "jonathan(see a@b)smith@x.test",
        '"john,smith@x"@corp.test',
        '"robert smith@x.test"@relay.test',  # enclosing match, not the inner email
        "(Robert x@y)robert@x.test",
    ],
)
def test_an_inner_at_sign_never_cuts_off_the_enclosing_address(email: str) -> None:
    r = redact(_cc(f"mail {email} now"), key=KEY)
    assert r.verified is True
    assert r.surrogate_count == {"email": 1}
    assert _only_surrogate_left(r, "mail ", " now"), r.text


@pytest.mark.parametrize(
    "text",
    [
        'x=\\"jonathan smith\\"@x.test y',  # JSON-escaped quotes: evidence is stored as JSON
        'C:\\"jonathan\\"@x.test y',
        '"jonathan\\"@x.test y',
        '{\\"to\\":\\"jo smith\\"@x.test\\"} y',
    ],
)
def test_a_json_escaped_quoted_local_part_is_redacted(text: str) -> None:
    r = redact(_cc(text), key=KEY)
    assert r.verified is True
    assert "email" in r.surrogate_count
    for word in ("jonathan", "smith"):
        assert word not in r.text, r.text


@pytest.mark.parametrize(
    "text", ["pay to @@@@4111 1111 1111 1111", "x@@@@ana@x.test", "@@@@@@@@ 12345678"]
)
def test_surrogates_are_never_taken_for_a_domain_literal(text: str) -> None:
    """'@[CARD:...]' looked like a domain literal, so each pass made a new match and 4+
    glued '@' exhausted the passes: verified=False on a fully redacted text."""
    import bok_core.boundary.redact as m

    assert m._DETECTORS["email"].search("@[CARD:abcdefghijkl]") is None
    r = redact(_cc(text), key=KEY)
    assert r.verified is True


# Differential guard. The REFERENCE is the email pattern applied position by position
# (finditer), with no shortcut; the fast @-driven scan must cover at least every character
# a reference match covers. p13's corpus shape: quotes, \", parentheses, '@', spaces,
# commas, escapes, brackets, Mc and accented letters, and real emails.
_BS = chr(92)
_DIFF_CHARS = [
    *"aaaabbbcxyz019",
    *"@@@@",
    *'"""',
    "(",
    ")",
    _BS,
    " ",
    " ",
    ".",
    "-",
    "\n",
    ",",
    "[",
    "]",
    ":",
    "!",
    "'",
    "\u093e",
    "\u00e9",
]
_DIFF_TOKENS = [
    "@",
    '"',
    "(",
    ")",
    _BS + '"',
    "a@b",
    '"a b@c"',
    "(x@y)",
    ".test",
    "x.test",
    "[1.2.3.4]",
    "[IPv6:1::2]",
    "jo",
    "smith",
    " ",
    "@x.test",
    '""',
    "()",
    "((a)b)",
    "a" * 30,
    " " * 3,
    "ana@x.test",
    '"jo smith"@x.test',
    "jo(c)@x.test",
    # quoted strings longer than 65 characters: a quoted-pair is 2 characters per item
    '"' + _BS + "a" * 1 + (_BS + "a") * 39 + ' smith"@x.test',
    '"x' + _BS * 2 + (_BS + "q") * 35 + ', jonathan"@x.test',
    (_BS + "a") * 30,
    _BS + '"jo smith' + _BS + '"@x.test',
]
_DIFF_PLAIN = st.one_of(
    st.lists(st.sampled_from(_DIFF_CHARS), min_size=1, max_size=40).map("".join),
    st.lists(st.sampled_from(_DIFF_TOKENS + _DIFF_CHARS), min_size=1, max_size=14).map("".join),
)
# Plain, and wrapped as JSON evidence is stored: once, as an object value, and twice.
_DIFF_CORPUS = st.one_of(
    _DIFF_PLAIN,
    _DIFF_PLAIN.map(json.dumps),
    _DIFF_PLAIN.map(lambda t: json.dumps({"dom": t, "cc": "bob"})),
    _DIFF_PLAIN.map(lambda t: json.dumps(json.dumps(t))),
)


def _reference_email_cover(text: str) -> set[int]:
    import bok_core.boundary.redact as m

    return {i for mt in m._DETECTORS["email"].finditer(text) for i in range(*mt.span())}


@pytest.mark.parametrize(
    "text",
    [
        "x " + "a" * 70 + '"q"@x.test',  # the 64-item cap binds inside the run
        '"q" ' + "b" * 80 + "@x.test",
        "(c) " + "c" * 90 + '(d)"q"@x.test',
        'x "ab' + chr(10) + "cd ef@x.test",  # a line break between the quote and the breaker
    ],
)
def test_the_64_item_cap_gives_the_same_start_as_the_reference_scan(text: str) -> None:
    """Inside a run of local-part characters a later start parses one item fewer; when
    the 64-item cap binds, the leftmost successful start is inside the run."""
    import bok_core.boundary.redact as m

    reference = [mt.span() for mt in m._DETECTORS["email"].finditer(text)]
    assert list(m._find_emails(text)) == reference


@settings(max_examples=1500, deadline=None)
@given(raw=_DIFF_CORPUS)
def test_the_fast_email_scan_covers_everything_the_reference_scan_covers(raw: str) -> None:
    """For EVERY email scan (RFC quoting, JSON-escaped quoting, nested-JSON quoting) the
    reference is that scan's own pattern applied position by position."""
    import bok_core.boundary.redact as m

    text = m._normalise(raw)
    for scan in m._EMAIL_SCANS:
        reference = {
            i
            for mt in scan.pattern.finditer(text)
            # the declared window: a local part starting > 256 before its "@" is not covered
            if scan.parse(text, mt.start())[0] - mt.start() <= m._EMAIL_LOOKBACK
            for i in range(*mt.span())
        }
        fast = {i for start, end in scan.find(text) for i in range(start, end)}
        missed = reference - fast
        assert not missed, (scan.name, text, "".join(text[i] for i in sorted(missed)))
    if chr(92) not in text:  # without a backslash the scans cannot differ (_only_with_backslash)
        results = {tuple(scan.find(text)) for scan in m._EMAIL_SCANS}
        assert len(results) == 1, (text, results)


# --- Task 8b fix round 3 ----------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        json.dumps({"dom": 'mail "jonathan smith"@x.test now'}),
        json.dumps({"dom": '"jonathan"@x.test'}),
        json.dumps({"to": '"jo smith"@x.test', "cc": "bob"}),
        json.dumps(['"jonathan smith"@x.test']),
        'x=\\"jonathan smith\\"@x.test y "z"',
        '<a title="\\"jonathan smith\\"@x.test">',
        json.dumps(json.dumps({"dom": 'mail "jonathan smith"@x.test now'})),  # twice-encoded
        json.dumps({"dom": '"jo\\"nathan"@x.test'}),  # a quoted-pair inside, then JSON
    ],
)
def test_a_quoted_local_part_inside_json_is_redacted(text: str) -> None:
    """The RFC quoted string commits whenever any later unescaped quote exists on the
    line -- true of every real JSON document -- so the JSON form was never tried."""
    r = redact(_cc(text), key=KEY)
    assert r.verified is True
    for word in ("jonathan", "smith", "nathan"):
        assert word not in r.text, r.text


_BS2 = chr(92)


@pytest.mark.parametrize(
    "text",
    [
        '"' + (_BS2 + "a") * 40 + ' smith"@x.test',  # reference (0, 95); fast had (88, 95)
        '"x' + _BS2 * 2 + (_BS2 + "q") * 35 + ', jonathan"@x.test',
        "mail "
        + '"'
        + _BS2 * 2
        + _BS2.join(["fileserver01", "departments", "accounts", "payable", "jonathan smith"])
        + '"@x.test now',
    ],
)
def test_a_quoted_string_longer_than_65_characters_is_not_cut(text: str) -> None:
    """A quoted-pair is 2 characters, so 64 items span up to 129; the enclosure bound
    counted 65 characters and cut the window inside the string."""
    import bok_core.boundary.redact as m

    reference = [mt.span() for mt in m._DETECTORS["email"].finditer(text)]
    assert list(m._find_emails(text)) == reference
    r = redact(_cc(text), key=KEY)
    assert r.verified is True
    for word in ("smith", "jonathan", "fileserver01"):
        assert word not in r.text, r.text


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


@st.composite
def _iban_national(draw: st.DrawFn, *, any_case_gapped: bool = False) -> str:
    """National display formats: country code, optional gap, check digits, then 11-30
    letters/digits cut into groups of ANY width by covered gaps, either case.

    A gapped country code is upper case unless `any_case_gapped` and the BBAN is
    digit-heavy (>= 8 digits). Any-case gapped codes go only into SEPARATED documents: glued
    directly after a letter they are a declared gap (indistinguishable from "ref 4111")."""
    cc = draw(st.sampled_from(["GB", "gb", "MT", "IT", "Fr"]))
    check = draw(st.from_regex(r"[0-9]{2}", fullmatch=True))
    body = draw(st.from_regex(r"[A-Za-z0-9]{11,30}", fullmatch=True))
    cuts = sorted(set(draw(st.lists(st.integers(1, len(body) - 1), max_size=6))))
    pieces = [body[a:b] for a, b in zip([0, *cuts], [*cuts, len(body)], strict=True)]
    gap = draw(st.sampled_from(["", " ", "-"]))
    if gap and not (any_case_gapped and sum(ch.isdigit() for ch in body) >= 8):
        cc = cc.upper()
    return f"{cc}{gap}{check}" + "".join(draw(_IBAN_GAP) + p for p in pieces)


_ATEXT = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]"

_EMAIL_LOCAL = st.one_of(
    st.from_regex(rf"{_ATEXT}{{1,10}}(\.{_ATEXT}{{1,6}})?", fullmatch=True),
    st.from_regex(r'"[a-z ]{1,8}"', fullmatch=True),
    st.from_regex(r'"[a-z]{1,4}\\"[a-z ]{1,4}"', fullmatch=True),  # quoted-pair
    st.from_regex(r"[a-z]{1,4}\([a-z]{1,6}\)", fullmatch=True),
    st.from_regex(r"[a-z]{1,4}\([a-z]{1,3}\([a-z]{1,3}\)[a-z]{0,3}\)", fullmatch=True),
)

_EMAIL_DOMAIN = st.one_of(
    st.from_regex(r"[a-z]{1,8}\.test", fullmatch=True),
    st.from_regex(r"\[[0-9]{1,3}(\.[0-9]{1,3}){3}\]", fullmatch=True),
    st.from_regex(r"\[IPv6:[0-9a-f]{1,4}(:[0-9a-f]{1,4}){2,5}\]", fullmatch=True),
)


@st.composite
def _email(draw: st.DrawFn) -> str:
    local = draw(_EMAIL_LOCAL)
    return f"{local}@{draw(_EMAIL_DOMAIN)}"


_TAGGED = st.one_of(
    st.tuples(st.just("email"), st.from_regex(r"[a-z]{1,8}@[a-z]{1,8}\.test", fullmatch=True)),
    st.tuples(st.just("email"), _email()),
    st.tuples(st.just("iban"), _iban_national()),
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
            out.append(draw(st.sampled_from(_DASHES)))
        elif ch == "/":
            out.append(draw(st.sampled_from(["/", "\u2044", "\u2215", "\uff0f", "\u2571"])))
        elif ch == "." and kind != "email":
            out.append(draw(st.sampled_from([".", "\u3002", "\uff61", "\uff0e", "\u00b7"])))
        elif ch.isdigit() and draw(st.integers(0, 3)) == 0:
            out.append(chr(zero + int(ch)))
        else:
            out.append(ch)
        if ch.isdigit():
            out.append(draw(st.sampled_from(_BETWEEN_DIGITS)))
        elif kind == "email" and draw(st.integers(0, 5)) == 0:
            out.append(draw(st.sampled_from(["\u0301", "\u0308", "\u20dd", "\u200d"])))
    return kind, "".join(out)


_DASHES = ["-", "\u2013", "\u2014", "\u2212", "\u2011", "\u30fc", "\u2500", "\u2796"]

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
    chr(0xD800),  # lone surrogate (Cs)
    "\ue000",  # private use (Co)
    "\u0378",  # unassigned (Cn)
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


_TAGGED_SEPARATED = st.one_of(
    _TAGGED, st.tuples(st.just("iban"), _iban_national(any_case_gapped=True))
)


@given(tagged=st.lists(_TAGGED_SEPARATED.flatmap(_noisy), min_size=1, max_size=6))
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


# --- JSON evidence property (needs the strategies above) ---------------------------------

_WORDS = st.from_regex(r"[a-z ]{0,16}", fullmatch=True)


@settings(max_examples=300, deadline=None)
@given(prefix=_WORDS, email=_email(), suffix=_WORDS)
def test_an_email_embedded_in_json_evidence_leaves_no_local_part_word(
    prefix: str, email: str, suffix: str
) -> None:
    """The depth-1 GUARANTEE: evidence is stored as JSON. Whatever covered email sits in
    the text, the JSON form of that text must lose every local-part word of 4+ characters."""
    _local_part_words_are_gone(prefix, email, suffix, depth=1)


# --- Task 8b fix round 4: decoded text plus ONE layer of JSON escaping -------------------
#
# The contract (INTERFACE-CONTRACT.md 1.3) is narrowed: redact() covers DECODED text plus
# one layer of JSON string escaping. Deeper encodings are covered only for quoted local
# parts without an inner escaped quote; HTML entities, \uXXXX / \xXX escapes and
# percent-encoding are not decoded. Callers redact string values BEFORE serialising.


def _local_part_words_are_gone(prefix: str, email: str, suffix: str, depth: int) -> None:
    """Whatever covered email sits in the text, the JSON form of that text, encoded
    `depth` times, must verify and lose every local-part word of 4+ characters."""
    text = f"{prefix} {email} {suffix}"
    local = email.rsplit("@", 1)[0]
    words = {w for w in re.findall(r"[A-Za-z0-9]{4,}", local) if w not in text.replace(email, "")}
    for document in (json.dumps({"k": text}), json.dumps([text, "x"])):
        for _ in range(depth - 1):
            document = json.dumps(document)
        r = redact(_cc(document), key=KEY)
        assert r.verified is True, r.failures
        for word in words:  # surrogates are letters a-p: "aaaa" can occur inside one
            assert word not in _leftover(r.text), (document, r.text)


# Every covered local-part shape EXCEPT a quoted string with an inner escaped quote
# ('"ab\"cd"'): the shape the contract covers when JSON is encoded twice.
_EMAIL_LOCAL_NO_INNER_QUOTE = st.one_of(
    st.from_regex(rf"{_ATEXT}{{1,10}}(\.{_ATEXT}{{1,6}})?", fullmatch=True),
    st.from_regex(r'"[a-z ]{1,8}"', fullmatch=True),
    st.from_regex(r"[a-z]{1,4}\([a-z]{1,6}\)", fullmatch=True),
    st.from_regex(r"[a-z]{1,4}\([a-z]{1,3}\([a-z]{1,3}\)[a-z]{0,3}\)", fullmatch=True),
)


@settings(max_examples=300, deadline=None)
@given(
    prefix=_WORDS,
    local=_EMAIL_LOCAL_NO_INNER_QUOTE,
    domain=_EMAIL_DOMAIN,
    suffix=_WORDS,
)
def test_twice_encoded_json_is_covered_for_quoted_local_parts_without_inner_quotes(
    prefix: str, local: str, domain: str, suffix: str
) -> None:
    """Depth 2 is covered for the declared shape only. Depth 1 (every covered shape) is
    test_an_email_embedded_in_json_evidence_leaves_no_local_part_word."""
    _local_part_words_are_gone(prefix, f"{local}@{domain}", suffix, depth=2)


def test_twice_encoded_json_with_an_inner_escaped_quote_is_a_declared_gap() -> None:
    """DECLARED GAP, pinned. Encoded twice, the inner quoted-pair of 'jonathan\\"smith'
    becomes a 7-backslash run whose reading no scan takes, and "jonathan" survives with
    verified=True. Once encoded it is covered. The contract's remedy -- redact the value,
    THEN serialise -- covers it at any depth. If this test starts failing because the
    word is gone, the gap has closed: update the declared-gaps lists."""
    value = 'mail "jonathan\\"smith"@x.test now'
    once = redact(_cc(json.dumps({"k": value})), key=KEY)
    assert once.verified is True
    assert "jonathan" not in once.text

    twice = redact(_cc(json.dumps(json.dumps({"k": value}))), key=KEY)
    assert twice.verified is True
    assert "jonathan" in twice.text  # the declared gap

    safe = redact(_cc(value), key=KEY).labelled().value
    assert "jonathan" not in json.dumps(json.dumps({"k": safe}))


@pytest.mark.parametrize(
    "value",
    [
        'mail "jonathan smith"@x.test now',  # the JSON scan's span began at the quote
        '"jonathan"@x.test',
        "line\nana@x.test",  # the walk back stopped at the backslash of "\n"
        "\u00e9 12345678",  # ensure_ascii writes \u00e9; the account began inside it
        "\u0661\u0662\u0663\u0664 5678 tail",  # Arabic-Indic digits, escaped by json
    ],
)
def test_redacted_json_still_parses(value: str) -> None:
    """A span starting or ending INSIDE an escape sequence left '\\[EMAIL:...]' or
    '\\u00e[ACCOUNT:...]', and json.loads failed with 'Invalid \\escape'. Spans are
    widened to whole escapes."""
    r = redact(_cc(json.dumps({"dom": value})), key=KEY)
    assert r.verified is True
    assert isinstance(json.loads(r.text)["dom"], str), r.text


@pytest.mark.parametrize(
    ("text", "span", "widened"),
    [
        (f"ab{_BS}u0041cd", (4, 6), (2, 8)),  # starts inside A
        (f"ab{_BS}u0041cd", (0, 4), (0, 8)),  # ends inside A
        (f"x{_BS}{_BS}y", (2, 4), (1, 4)),  # starts on the escaped backslash of \\
        (f"x{_BS}{_BS}y", (0, 2), (0, 3)),  # ends on the escaping backslash of \\
        (f"a{_BS}nb", (2, 4), (1, 4)),  # starts on the n of \n
        (f"a{_BS}zz", (0, 2), (0, 3)),  # ends on an escaping backslash
        (f"a{_BS}{_BS}nb", (3, 5), (3, 5)),  # \\ then a literal n: no escape is cut
        ("plain", (1, 3), (1, 3)),
    ],
)
def test_a_span_is_widened_to_whole_escape_sequences(
    text: str, span: tuple[int, int], widened: tuple[int, int]
) -> None:
    """Both ends. In real JSON no detector match crosses a backslash and then ends inside
    an escape, so the end side is pinned here rather than by the property."""
    import bok_core.boundary.redact as m

    assert m._whole_escapes(text, *span) == widened


_JSON_TEXT = st.from_regex("[a-z\u00e9 ]{0,12}", fullmatch=True)  # e-acute: \u00e9 in JSON
_JSON_VALUE = st.one_of(
    _JSON_TEXT,
    st.tuples(_JSON_TEXT, _TAGGED.flatmap(_noisy), _JSON_TEXT).map(
        lambda t: f"{t[0]} {t[1][1]} {t[2]}"
    ),
    # the identifier IS the whole value: it sits right against the JSON string's quotes
    _TAGGED.map(lambda t: t[1]),
)


@settings(max_examples=500, deadline=None)
@given(
    obj=st.dictionaries(
        st.from_regex(r"[a-z]{1,6}", fullmatch=True), _JSON_VALUE, min_size=1, max_size=4
    ),
    ensure_ascii=st.booleans(),
    compact=st.booleans(),
)
def test_redacted_json_evidence_stays_parseable(
    obj: dict[str, str], ensure_ascii: bool, compact: bool
) -> None:
    """Random JSON objects whose string values hold covered identifiers (with Unicode
    separators, digits and format characters, which ensure_ascii writes as \\uXXXX):
    the redacted document verifies and still parses, with the same keys."""
    separators = (",", ":") if compact else None
    r = redact(_cc(json.dumps(obj, ensure_ascii=ensure_ascii, separators=separators)), key=KEY)
    assert r.verified is True, r.failures
    loaded = json.loads(r.text)
    assert isinstance(loaded, dict)
    assert loaded.keys() == obj.keys()


# One layer of JSON escaping includes the two-character escapes of whitespace and slash:
# DOM table innerText is TAB-separated, and json.dumps writes a TAB as backslash + "t".
_TAB, _LF, _CR = chr(9), chr(10), chr(13)


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        (_TAB.join(["4111", "1111", "1111", "1111"]), "card"),
        (_LF.join(["4111", "1111", "1111", "1111"]), "card"),
        (_CR + _LF + "4111" + _CR + _LF + "1111 1111" + _TAB + "1111", "card"),
        ("4111/1111/1111/1111", "card"),
        (_TAB.join(["GB82", "WEST", "1234", "5698", "7654", "32"]), "iban"),
        (_LF.join(["IT60 X", "05428", "11101", "000000123456"]), "iban"),
        ("555" + _TAB + "010" + _TAB + "0100", "phone"),
        ("(555)" + _LF + "010-0100", "phone"),
        (_TAB.join(["12", "34", "56", "78"]), "account"),
    ],
)
def test_json_escaped_whitespace_between_groups_is_a_gap(value: str, kind: str) -> None:
    """json.dumps({"k": "4111<TAB>1111<TAB>1111<TAB>1111"}) is '4111' + backslash-t + ...:
    one layer of JSON escaping, so it is covered. It passed fully unredacted with
    verified=True; the escapes \\t \\n \\r \\f \\b and \\/ are now gap characters."""
    import bok_core.boundary.redact as m

    document = json.dumps({"k": f"pay {value}; now"})  # ";": an IBAN absorbs a short word
    r = redact(_cc(document), key=KEY)
    assert r.verified is True, r.failures
    assert kind in r.surrogate_count, (document, r.text)
    decoded = json.loads(r.text)["k"]
    assert decoded.startswith("pay ") and decoded.endswith("; now"), decoded
    assert not _fragments(m._normalise(value)) & _fragments(_leftover(decoded)), decoded


def test_a_json_escaped_iban_keeps_its_plain_surrogate() -> None:
    """The escape is a separator, not part of the IBAN: the canonical form drops it, so
    the TAB-separated IBAN in JSON joins with the same IBAN in plain text."""
    plain = redact(_cc("pay GB82 WEST 1234 5698 7654 32; now"), key=KEY).text
    value = _TAB.join(["GB82", "WEST", "1234", "5698", "7654", "32"])
    in_json = json.loads(redact(_cc(json.dumps({"k": f"pay {value}; now"})), key=KEY).text)["k"]
    assert in_json == plain


@settings(max_examples=300, deadline=None)
@given(tagged=st.lists(_TAGGED_SEPARATED, min_size=1, max_size=5))
def test_identifiers_in_json_evidence_are_redacted_whole(tagged: list[tuple[str, str]]) -> None:
    """The depth-1 guarantee for every kind, not only emails: identifiers whose groups
    are separated by TAB, LF or CR (the strategies' separators include them) are written
    by json.dumps as two-character escapes. No 4-character fragment may survive in the
    DECODED redacted value, and the document must still parse."""
    import bok_core.boundary.redact as m

    text = "<< " + " ; ".join(v for _, v in tagged) + " >>"
    for document in (json.dumps({"k": text}), json.dumps([text, "x"])):
        r = redact(_cc(document), key=KEY)
        assert r.verified is True, r.failures
        loaded = json.loads(r.text)
        decoded = loaded["k"] if isinstance(loaded, dict) else loaded[0]
        left = _leftover(decoded)
        for _, value in tagged:
            normal = m._normalise(value)
            assert not _fragments(normal) & _fragments(left), (document, decoded)


# --- Task 8b fix round 5: \b and \/ are decoded the way a JSON decoder would --------------
#
# json.dumps writes a decoded BACKSPACE (U+0008, a control character that normalisation
# strips at no cost) as the two characters backslash + "b", and PHP's json_encode writes
# every "/" as backslash + "/". Normalisation now removes an escaping "\b" and turns an
# escaping "\/" into "/": the result is still valid JSON, and it is what detection would
# have seen in the decoded text.

_BK = chr(8)


def _php(document: str) -> str:
    """PHP json_encode's default: every "/" escaped."""
    return document.replace("/", _BS + "/")


@pytest.mark.parametrize(
    "value",
    [
        _BK.join(["4111", "", "", "", "1111", "", "", "", "1111", "", "", "", "1111"]),
        "4111" + _TAB + _BK + " " + _TAB + "1111" + _TAB + "1111" + _TAB + "1111",
        "12345" + _BK * 4 + "678",
        "GB82" + _BK * 4 + "WEST12345698765432",
        "jonathan" + _BK + "@x.test",
        "ana@exa" + _BK + "mple.test",
        "jo" + _BK + "nathan.smith@x.test",
    ],
)
def test_a_json_escaped_backspace_costs_nothing_as_in_decoded_text(value: str) -> None:
    """Decoded, a backspace is stripped and joins what it splits. In JSON text it was the
    2-character escape and counted as a gap unit (or ended an email): every value here
    kept a whole identifier or a 4+ character part of one with verified=True."""
    import bok_core.boundary.redact as m

    r = redact(_cc(json.dumps({"k": f"pay {value}; now"})), key=KEY)
    assert r.verified is True, r.failures
    decoded = json.loads(r.text)["k"]
    assert decoded.startswith("pay ") and decoded.endswith("; now"), decoded
    assert not _fragments(m._normalise(value)) & _fragments(_leftover(decoded)), decoded


@pytest.mark.parametrize(
    "value",
    [
        "mail jonathan/smith@x.test now",
        "mail jonathan.smith/sales@x.test now",
        "pay 4111/1111/1111/1111; now",
        "pay GB82/WEST/1234/5698/7654/32; now",
    ],
)
def test_a_php_escaped_slash_is_a_slash(value: str) -> None:
    """{"k": "mail jonathan\\/smith@x.test now"} -> "mail jonathan[EMAIL]": the escaped
    slash ended the local part. One layer of JSON escaping: it is a "/"."""
    import bok_core.boundary.redact as m

    r = redact(_cc(_php(json.dumps({"k": value}))), key=KEY)
    assert r.verified is True, r.failures
    decoded = json.loads(r.text)["k"]
    identifier = value.split(" ")[1].rstrip(";")
    assert not _fragments(m._normalise(identifier)) & _fragments(_leftover(decoded)), decoded


@pytest.mark.parametrize(
    ("text", "normal"),
    [
        (f"a{_BS}bc", "ac"),  # an escaping \b is removed
        (f"a{_BS}/c", "a/c"),  # an escaping \/ is a slash
        (f"C:{_BS}{_BS}bin", f"C:{_BS}{_BS}bin"),  # \\ then b: a literal backslash
        (f"x{_BS}{_BS}/y", f"x{_BS}{_BS}/y"),  # \\ then /: a literal backslash
        (f"{_BS}{_BS}{_BS}b", f"{_BS}{_BS}"),  # \\ then \b
        (f"{_BS}{_BS}{_BS}/", f"{_BS}{_BS}/"),  # \\ then \/
        (f"{_BS}{_BS}{_BS}{_BS}b", f"{_BS}{_BS}{_BS}{_BS}b"),  # \\ \\ then b
        (f"{_BS}nb {_BS}tb", f"{_BS}nb {_BS}tb"),  # other escapes untouched
    ],
)
def test_only_an_escaping_backslash_is_decoded(text: str, normal: str) -> None:
    """A backslash escapes only after an even run of backslashes; '\\\\b' is a literal
    backslash followed by 'b' and must survive as written."""
    import bok_core.boundary.redact as m

    assert m._normalise(text) == normal


@st.composite
def _with_backspaces(draw: st.DrawFn, tagged: tuple[str, str]) -> tuple[str, str]:
    """Backspaces anywhere in an identifier -- between digit/IBAN groups, inside an email
    local part or domain. Decoded, they are stripped; json.dumps writes each as '\\b'."""
    kind, value = tagged
    out = []
    for ch in value:
        out.append(ch)
        if draw(st.integers(0, 4)) == 0:
            out.append(_BK * draw(st.integers(1, 4)))
    return kind, "".join(out)


@settings(max_examples=300, deadline=None)
@given(
    tagged=st.lists(_TAGGED_SEPARATED.flatmap(_with_backspaces), min_size=1, max_size=5),
    php=st.booleans(),
)
def test_identifiers_with_backspaces_and_php_slashes_in_json_are_redacted_whole(
    tagged: list[tuple[str, str]], php: bool
) -> None:
    """The depth-1 property with the two decoder-normalised escapes: backspaces inside
    any identifier, and PHP-style '\\/' for every slash (separators, atext)."""
    import bok_core.boundary.redact as m

    text = "<< " + " ; ".join(v for _, v in tagged) + " >>"
    for document in (json.dumps({"k": text}), json.dumps([text, "x"])):
        document = _php(document) if php else document
        r = redact(_cc(document), key=KEY)
        assert r.verified is True, r.failures
        loaded = json.loads(r.text)
        decoded = loaded["k"] if isinstance(loaded, dict) else loaded[0]
        left = _leftover(decoded)
        for _, value in tagged:
            assert not _fragments(m._normalise(value)) & _fragments(left), (document, decoded)


@pytest.mark.parametrize(
    "obj",
    [
        {"k": "ana@x.test"},
        {"k": "x", "m": "ana@x.test"},
        ["a", "ana@x.test"],
        {"to": ["jo@x.test", "ana@x.test"]},
        {"k": "jonathan.smith@x.test", "n": 1},
    ],
)
@pytest.mark.parametrize("compact", [False, True])
def test_an_email_that_is_a_whole_json_value_does_not_swallow_the_structure(
    obj: dict[str, object] | list[str], compact: bool
) -> None:
    """{"k": "ana@x.test"} was redacted to {"[EMAIL:...]"}: the RFC grammar read
    'k": "ana' as a local part -- atext "k", the quoted string '": "', atext "ana" -- so
    the key and the JSON punctuation went into the span and the document no longer
    parsed. A quoted string holding only JSON punctuation (whitespace : , [ ] { }) is not
    a quoted local part."""
    separators = (",", ":") if compact else None
    r = redact(_cc(json.dumps(obj, separators=separators)), key=KEY)
    assert r.verified is True, r.failures
    loaded = json.loads(r.text)
    if isinstance(obj, dict):
        assert isinstance(loaded, dict) and loaded.keys() == obj.keys()
    else:
        assert isinstance(loaded, list) and len(loaded) == len(obj)
    assert "ana" not in _leftover(r.text) and "jonathan" not in _leftover(r.text)


def test_a_json_separator_is_never_a_quoted_local_part() -> None:
    """Declared: a quoted string that is a JSON separator (whitespace and brackets around
    ":" or ",") ends the local part, so 'jo", "smith@x.test' keeps 'jo", "' -- the
    address after it is still redacted. A quoted string of whitespace alone is not a
    separator: 'jonathan" "smith@x.test' is redacted whole."""
    r = redact(_cc('mail jo", "smith@x.test now'), key=KEY)
    assert r.verified is True
    assert "smith" not in _leftover(r.text)
    assert 'jo", "' in r.text
    whole = redact(_cc('mail jonathan" "smith@x.test now'), key=KEY)
    assert _leftover(whole.text) == "mail " + chr(0) + " now", whole.text


# --- Task 10 step 0 (carried Task 8b breaker ruling): non-string neighbouring values ------
#
# The round-5 exclusion covered only punctuation-only quoted strings, so a JSON separator
# that holds a NON-STRING value (': 1, ', ', 1, ', ': [1, ', ': 7}, ') was still read as a
# quoted local part and swallowed the key or the previous value into the email's span:
# {"a": [1, "ana@x.test"]} redacted to text that no longer parsed, with verified=True.
# Any quoted string whose content starts (after whitespace and brackets) with ':' or ','
# is now not a quoted local part.


@pytest.mark.parametrize(
    "obj",
    [
        {"a": [1, "ana@x.test"]},
        {"a": [True, "ana@x.test"]},
        {"a": [None, "ana@x.test"]},
        [{"id": 7}, "ana@x.test"],
        {"rows": [{"n": 1}, "ana@x.test"]},
        ["jonathan", {"a": 1}, "smith@x.test"],  # regression vs 4bcec16
        ["x", 1, "ana@x.test"],
        ["x", 1.5, "ana@x.test"],
        ["x", -1, "ana@x.test"],
        ["x", [1, 2], "ana@x.test"],
        ["x", {}, "ana@x.test"],
        {"a": 1, "b": "ana@x.test"},
        {"name": "jonathan", "n": 5, "e": "smith@x.test"},
        ["a", 1, 2, "ana@x.test"],
    ],
)
@pytest.mark.parametrize("compact", [False, True])
def test_a_non_string_neighbour_is_never_swallowed_into_an_email(
    obj: dict[str, object] | list[object], compact: bool
) -> None:
    separators = (",", ":") if compact else None
    document = json.dumps(obj, separators=separators)
    r = redact(_cc(document), key=KEY)
    assert r.verified is True, r.failures
    loaded = json.loads(r.text)
    assert _shape(loaded) == _shape(obj), (document, r.text)
    assert "ana" not in _leftover(r.text) and "smith" not in _leftover(r.text)


def _shape(value: object) -> object:
    """The JSON structure with every string replaced by one marker: non-string values,
    keys' count and nesting must survive redaction exactly."""
    if isinstance(value, str):
        return "S"
    if isinstance(value, list):
        return [_shape(v) for v in value]
    if isinstance(value, dict):
        return [("S", _shape(v)) for v in value.values()]
    return value


# Numbers stay below 8 digits: a JSON number literal that IS an identifier (8+ digits) is
# replaced by an unquoted surrogate (declared in the contract), which is not what this
# property is about.
_JSON_SCALAR = st.one_of(
    _JSON_VALUE,
    st.integers(min_value=-999_999, max_value=999_999),
    st.floats(min_value=-9_999, max_value=9_999, allow_nan=False).map(lambda f: round(f, 2)),
    st.booleans(),
    st.none(),
)
_JSON_TREE = st.recursive(
    _JSON_SCALAR,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.from_regex(r"[a-z]{1,6}", fullmatch=True), children, max_size=4),
    ),
    max_leaves=12,
)


@settings(max_examples=500, deadline=None)
@given(
    obj=st.one_of(
        st.lists(_JSON_TREE, min_size=1, max_size=5),
        st.dictionaries(
            st.from_regex(r"[a-z]{1,6}", fullmatch=True), _JSON_TREE, min_size=1, max_size=5
        ),
    ),
    ensure_ascii=st.booleans(),
    compact=st.booleans(),
)
def test_redacted_json_with_any_neighbouring_values_keeps_its_structure(
    obj: object, ensure_ascii: bool, compact: bool
) -> None:
    """Numbers, booleans, null, nested arrays and objects as neighbours of identifiers:
    the redacted document verifies, parses, and keeps every non-string value and the
    nesting exactly; only string contents change."""
    separators = (",", ":") if compact else None
    r = redact(_cc(json.dumps(obj, ensure_ascii=ensure_ascii, separators=separators)), key=KEY)
    assert r.verified is True, r.failures
    assert _shape(json.loads(r.text)) == _shape(obj), r.text


@settings(max_examples=300, deadline=None)
@given(
    email=_email(),
    before=st.one_of(_JSON_TREE, st.just("jonathan")),
    after=_JSON_TREE,
)
def test_an_email_among_non_string_values_leaves_no_local_part_word(
    email: str, before: object, after: object
) -> None:
    """The depth-1 email guarantee with non-string neighbours in the same array."""
    local = email.rsplit("@", 1)[0]
    words = set(re.findall(r"[A-Za-z0-9]{4,}", local))
    document = json.dumps([before, email, after])
    others = json.dumps([before, after])
    r = redact(_cc(document), key=KEY)
    assert r.verified is True, r.failures
    assert _shape(json.loads(r.text)) == _shape([before, email, after]), r.text
    for word in words - {w for w in words if w in others}:
        assert word not in _leftover(r.text), (document, r.text)


def test_a_quoted_local_part_starting_with_a_separator_is_a_declared_gap() -> None:
    """DECLARED GAP, pinned: a quoted string whose content starts (after whitespace and
    brackets) with ',' or ':' is never a quoted local part, so '",jonathan"@x.test' keeps
    ',jonathan"' -- the price of never reading a JSON separator as an address."""
    r = redact(_cc('mail ",jonathan"@x.test now'), key=KEY)
    assert r.verified is True
    assert "jonathan" in r.text
    whole = redact(_cc('mail "jonathan,"@x.test now'), key=KEY)  # ',' later: covered
    assert "jonathan" not in _leftover(whole.text), whole.text


@pytest.mark.parametrize(
    ("content", "is_separator"),
    [
        (": 1, ", True),
        (", 1, ", True),
        ("]}, ", True),
        (" \t: ", True),
        (",jo", True),
        ("[jo", False),
        ("{jo}", False),
        (" jo", False),
        ("jo, ", False),
        ("a:b", False),
    ],
)
def test_the_separator_lookaheads_test_only_the_start_of_the_content(
    content: str, is_separator: bool
) -> None:
    """Pinned directly: the other scans can mask a broken lookahead (a missing backslash
    in the escaped form turned its bracket class into a single character test and every
    property still passed). The escaped form also skips backslashes."""
    import bok_core.boundary.redact as m

    assert (re.match(m._NOT_PUNCTUATION, content) is None) is is_separator
    backslash = chr(92)
    escaped = content.replace(" ", backslash + " ").replace("[", backslash + "[")
    assert (re.match(m._NOT_ESCAPED_PUNCTUATION, escaped) is None) is is_separator


def test_a_json_number_that_is_an_identifier_breaks_the_document_declared() -> None:
    """DECLARED, pinned: the valid-JSON claim holds only while no JSON number literal is
    itself an identifier. A 9-digit number is a routing number; its surrogate is written
    unquoted, so the document no longer parses. Callers redact values before
    serialising."""
    r = redact(_cc(json.dumps({"n": 123456789})), key=KEY)
    assert r.verified is True
    assert "123456789" not in r.text
    with pytest.raises(json.JSONDecodeError):
        json.loads(r.text)
