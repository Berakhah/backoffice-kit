"""Normalise -> detect (all detectors, spans merged) -> keyed surrogate -> RE-DETECT.

R1 rewrote this module. Three things were wrong, and each was the kind of wrong that
ships green:

1. The verification pass could not fail. It searched the output for the very strings it
   had just replaced, so absent a deliberately injected leak the answer was always "all
   clear". Verification now RE-RUNS EVERY DETECTOR over the output.

2. `_force_leak=` was a production keyword argument whose entire function was to write a
   raw secret into a redacted document. It is gone; the test simulates a MISSED detection.

3. Surrogates were sha256(identifier)[:8] -- an unkeyed hash of a low-entropy value, so a
   "redacted" document was a lookup table. Surrogates are now HMAC-keyed.

What verification does and does NOT catch -- precisely. It fails if any covered detector
still matches anywhere in the output: an identifier whose substitution was skipped or
failed, or one that only becomes matchable once a neighbour has been substituted. It
CANNOT catch an identifier that substitution MANGLED into a shape no detector recognises:
when detectors substituted one after another, `phone` took the digit tail of
"NL91ABNA0417164300" and left "NL91ABNA[PHONE:..]", which matches nothing and so
verified. Verification is blind to that by construction, so it is prevented structurally
instead: every detector runs over the SAME text, overlapping matches are merged into one
span, and each span is replaced whole. A character any detector matched is always
redacted, whatever the detector order. Because of that, the digit detectors carry no
"not preceded/followed by a digit" guards: a match in the middle of a longer run can only
ADD coverage (it merges into the longer match), whereas a guard that refuses to match
glued text leaves a residue. Property tests pin it (per-kind counts; no 4-character
fragment of any identifier survives, separated, adjacent or glued).

And the result object no longer carries the identifiers it removed: see RedactionResult.
"""

from __future__ import annotations

import hmac
import re
import unicodedata
from hashlib import sha256

from pydantic import BaseModel, ConfigDict, Field

from bok_core.boundary.sensitivity import Labelled, Sensitivity

# What this module claims to detect, and what it does not. 00 section 4.2 names six
# classes. Both tuples are asserted by a test and declared in docs/methodology.md (a test
# keeps the two in step), so the gap is a declared limitation rather than a silent hole.
COVERED = ("email", "iban", "phone", "digit_run", "card", "tax_id", "routing", "account")
NOT_COVERED = ("person_name", "address")

MIN_KEY_BYTES = 32


class RedactionFailed(Exception):
    """Verification did not pass. This text is not safe to treat as REDACTED."""


# What the digit detectors accept BETWEEN two digits, after normalisation: nothing, or a
# run of 1-3 characters drawn from whitespace (space, TAB, CR, LF -- innerText of a table
# row is tab-separated), '.', '-' and '/'. So "4111  1111", "4111\t1111", "4111 - 1111"
# and "4111/1111" are all one run. Every Unicode space (Zs) and dash (Pd, U+2212) has
# already been mapped onto ASCII, and invisible characters removed (_normalise). Round 1
# accepted exactly one of space/hyphen/dot, and digit groups split any other way passed
# through with verified=True. The cost is over-redaction: rows of small numbers, prices,
# dates and IP addresses become `account`/`card`/`digit_run` (declared in methodology.md).
_GAP = r"[\s./\-]{0,3}"

# Person names and addresses need local NER (spaCy/GLiNER) and land in week 5. Until then
# a document containing a person's name is not REDACTED; it is CLIENT_CONFIDENTIAL.
#
# Order is the tie-break for LABELLING a merged span (the longest constituent match names
# it; on equal length, earlier wins). It does not decide what gets redacted.
_DETECTORS: dict[str, re.Pattern[str]] = {
    # No \b at either end: the local part may start mid-run ("...AAAAaaaa@a.test" after
    # an IBAN) and may be empty (a bare "@a.test" residue: in "a@a.test.aa@a.test" the
    # first match takes "a@a.test.aa"), and "ana@x.test12345678" ends at the TLD.
    # Every part is length-bounded (RFC 5321: local 64, domain 255, label 63), which also
    # keeps the scan linear on a long run of word characters with no "@".
    "email": re.compile(r"[\w.%+-]{0,64}@[\w.-]{1,255}\.[A-Za-z]{2,63}"),
    # Grouped in fours, every group -- the trailing 1-4 character group included --
    # preceded by the same 0-3 character gap the digit detectors accept, so one shape
    # covers compact (NL91ABNA0417164300: zero gaps), spaced, GB82-WEST-1234-...,
    # GB82<TAB>WEST..., "MT84  MALT  ...  01S" and mixed layouts. Single spaces only left
    # "GB82-WEST-[CARD]" and "MTLC  AST0  01S" behind. The grouped branch is tried FIRST:
    # with compact first, "GB00000A00AAAAAA AAAA0" matched compact up to the space and
    # stranded " AAAA0". Up to 31 groups (124 characters); IBANs glued at another
    # 4-alignment are caught by the overlapping scan (_OVERLAPPING). Groups are a fixed
    # 4 wide, so backtracking is bounded. Guarded, so a match never ends half-way
    # through a group.
    # Fallback: compact 11-128 characters, unguarded, so a token longer than the grouped
    # branch can take is consumed in bites rather than not at all (with a guard,
    # "GB12GB12..." verification failed closed).
    # Case-insensitive ("gb82 west ..." is the same IBAN, and an upper-case-only shape
    # leaked it). No left boundary at all, so "a@a.testGB68..." and "...0100GB00 0AAA..."
    # still yield an IBAN match. The cost is over-redaction of long codes that contain two
    # letters followed by two digits (hex hashes, SKUs) -- the safe direction.
    "iban": re.compile(
        r"[A-Z]{2}\d{2}"
        rf"(?:(?:{_GAP}[A-Z0-9]{{4}}){{2,31}}(?:{_GAP}[A-Z0-9]{{1,4}})?(?![A-Z0-9])"
        r"|[A-Z0-9]{11,128})",
        re.IGNORECASE,
    ),
    # Optional "+CC", then "(ddd)" or "ddd", then ddd and dddd, each gap independent.
    # Round 1 forced the two gaps to AGREE (a backreference, to keep a Diners card
    # "3056 930902 5904" from being labelled phone) and so "555 010-0100" passed through
    # unredacted. Labels are the span merge's job: the card match is longer and wins.
    "phone": re.compile(
        rf"(?:\+\d{{1,3}}{_GAP})?(?:\(\d{{3}}\)|\d{{3}}){_GAP}\d{{3}}{_GAP}\d{{4}}"
    ),
    # 20+ digits. Without it a 20-digit run, or a spaced run longer than 19, left a tail.
    "digit_run": re.compile(rf"\d(?:{_GAP}\d){{19,}}"),
    "card": re.compile(rf"\d(?:{_GAP}\d){{12,18}}"),
    # US EIN (12-3456789) and SSN/ITIN (123-45-6789) shapes, hyphenated only.
    "tax_id": re.compile(r"\d{2}-\d{7}|\d{3}-\d{2}-\d{4}"),
    "routing": re.compile(r"\d{9}"),
    # 8-12 digits (gaps allowed), so with `card` (13-19) and `digit_run` (20+) EVERY run of
    # 8 or more digits is redacted, however it is split. On a 9- or 10-digit tie
    # `routing` / `phone` / `tax_id` keep the label by rank.
    "account": re.compile(rf"\d(?:{_GAP}\d){{7,11}}"),
}

# Kinds whose identity is the digits alone: the HMAC input drops every separator, so
# "555-010-0100" and "(555) 010 0100" share one surrogate and joins survive layout.
_DIGIT_KINDS = frozenset({"phone", "digit_run", "card", "tax_id", "routing", "account"})

# Detectors scanned for OVERLAPPING matches (a match may start inside another match of
# the same detector). IBANs glued together at different 4-alignments
# ("GB000000AAAAAAAAAAGB00 00AA 0AAA ...") are not one run of groups: a non-overlapping
# scan resumes after the first match and strands the second IBAN's groups. Removing this
# scan was tried in round 3 and re-opened exactly that leak, so it stays -- at a declared
# cost: an inner match at another alignment can absorb a following 1-4 character word
# ("ST12345698765432 now" inside "GB82WEST12345698765432 now"), widening the span into a
# merged span whose surrogate is context-specific. That loses a join; it never leaks and
# never makes a false join. Bounded patterns only: one attempt per start position.
_OVERLAPPING: dict[str, re.Pattern[str]] = {
    kind: re.compile(rf"(?=({_DETECTORS[kind].pattern}))", _DETECTORS[kind].flags)
    for kind in ("iban",)
}

# Substitution can expose a new match (a surrogate's ']' ends a run that a neighbour's
# guard refused to end), so detect+substitute repeats until nothing more is found.
_MAX_PASSES = 4

# Test seam. A kind set here is MISSED: no span overlapping one of its matches is
# substituted, while detection (and so verification) stays on. That is how the
# verification pass is exercised against a genuine miss rather than a planted leak.
_SUBSTITUTION_DISABLED: dict[str, bool] = {}

# Surrogate digests are rendered in a DIGIT-FREE alphabet: a hex digest contains a run of
# 8-10 decimal digits ~5% of the time, which a detector would match. Same 4 bits per
# character as hex.
_HEX_TO_LETTERS = str.maketrans("0123456789abcdef", "abcdefghijklmnop")

_MINUS_SIGN = "\u2212"  # category Sm, not Pd, but used as a dash in typeset numbers

# Default_Ignorable_Code_Point, hard-coded from DerivedCoreProperties.txt of Unicode
# 15.0.0 -- the version Python 3.12's unicodedata implements (unidata_version). Python
# exposes no accessor for the property. Many are Cf (stripped anyway) but not all: CGJ
# U+034F and the variation selectors are Mn, the Hangul fillers are Lo, and each of them
# split a digit run invisibly and passed with verified=True.
_DEFAULT_IGNORABLE: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
# Not default-ignorable, but render as blank: braille pattern blank (So). The Hangul
# fillers are repeated here for the record; they are in the range table above.
_ALSO_INVISIBLE = (0x2800, 0x3164, 0x1160, 0x115F, 0xFFA0)
_INVISIBLE: frozenset[int] = frozenset(
    {cp for lo, hi in _DEFAULT_IGNORABLE for cp in range(lo, hi + 1)} | set(_ALSO_INVISIBLE)
)
# The only control characters kept: the whitespace ones, which are gap characters.
# Every other C0/C1 control (NUL, BS, ESC, DEL, NEL, ...) split a digit run.
_KEPT_CONTROLS = frozenset("\t\n\r\x0b\x0c")


def _normalise(text: str) -> str:
    """Structural, not per-character. After NFKD (compatibility DEcomposition, so every
    precomposed letter splits into base + combining mark):

    - every decimal digit of any script (Nd) -> its ASCII digit;
    - REMOVED from all text: every combining mark (Mn, Me) -- i.e. every diacritic, so
      "cafe\\u0301" and "caf\\u00e9" both become "cafe" -- every control character except
      TAB/LF/CR/VT/FF, every format character (Cf), every Default_Ignorable_Code_Point,
      and the blank-rendering characters above;
    - every Unicode space (Zs) -> ' '; every dash (Pd) and the minus sign -> '-';
    - then NFC, which only recomposes what is left (Hangul syllables).

    Decomposing first is what makes the mark rule structural: under NFKC, "e" + U+0301
    composes to "e-acute" (a letter, Ll), survives a strip of Mn, and breaks the
    `[A-Za-z]` TLD of "ana@x.te\\u0301st" -- a leak with verified=True.

    The redacted OUTPUT is this normalised text -- including the text around identifiers,
    so ligatures, superscripts, full-width forms, diacritics, bidi marks and ZWJ in emoji
    are normalised too. No offset map back into the original is provided.
    """
    out: list[str] = []
    for ch in unicodedata.normalize("NFKD", text):
        category = unicodedata.category(ch)
        if category in ("Cf", "Mn", "Me") or ord(ch) in _INVISIBLE:
            continue
        if category == "Cc" and ch not in _KEPT_CONTROLS:
            continue
        if category == "Nd":
            out.append(str(unicodedata.decimal(ch)))
        elif category == "Zs":
            out.append(" ")
        elif category == "Pd" or ch == _MINUS_SIGN:
            out.append("-")
        else:
            out.append(ch)
    return unicodedata.normalize("NFC", "".join(out))


def _canonical(kind: str, identifier: str) -> str:
    """The HMAC input: one identifier gets one surrogate whatever its layout or case.

    Digit kinds -> the digits alone; IBAN -> its letters and digits, upper case; email ->
    lower case.
    """
    if kind in _DIGIT_KINDS:
        return "".join(ch for ch in identifier if ch.isdigit())
    if kind == "iban":
        return "".join(ch for ch in identifier if ch.isalnum()).upper()
    return identifier.lower()


def _merged_spans(text: str) -> list[tuple[int, int, str, bool]]:
    """Every detector's matches over the same text; overlapping matches merged.

    Each merged span is labelled by its longest constituent match (earlier detector on a
    tie), so an IBAN containing a phone-shaped tail is one IBAN, not a residue. The flag
    is True when that labelling match covers the WHOLE span (a standalone identifier) and
    False when other matches widened it (a merged span) -- see _hmac_input.
    """
    found: list[tuple[int, int, int, str]] = []
    for rank, (kind, pattern) in enumerate(_DETECTORS.items()):
        if kind in _OVERLAPPING:
            matches = _OVERLAPPING[kind].finditer(text)
            found.extend((m.start(1), m.end(1), rank, kind) for m in matches)
        else:
            found.extend((m.start(), m.end(), rank, kind) for m in pattern.finditer(text))
    found.sort()

    # (start, end, label, missed, label_start, label_end)
    merged: list[tuple[int, int, str, bool, int, int]] = []
    best: tuple[int, int] = (0, 0)  # (length, -rank) of the current span's label
    for start, end, rank, kind in found:
        score = (end - start, -rank)
        missed = bool(_SUBSTITUTION_DISABLED.get(kind))
        if merged and start < merged[-1][1]:
            m_start, m_end, m_kind, m_missed, l_start, l_end = merged[-1]
            if score > best:
                best, m_kind, l_start, l_end = score, kind, start, end
            merged[-1] = (m_start, max(m_end, end), m_kind, m_missed or missed, l_start, l_end)
        else:
            best = score
            merged.append((start, end, kind, missed, start, end))
    return [
        (start, end, kind, (l_start, l_end) == (start, end))
        for start, end, kind, missed, l_start, l_end in merged
        if not missed
    ]


class RedactionResult(BaseModel):
    """R1: `surrogates: dict[original -> surrogate]` is gone -- it carried every piece of
    PII the redactor had just removed.

    `text` is excluded from repr()/str(): when verification FAILS, `text` still holds the
    surviving identifier, and the failed path is the one most likely to reach a log line
    or a traceback. `model_dump()` does include it -- it is the payload. A caller that
    persists an UNVERIFIED result's text must treat it as CLIENT_CONFIDENTIAL and route
    it through egress like the original document; `labelled()` refuses to relabel it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    text: str = Field(repr=False)
    verified: bool
    surrogate_count: dict[str, int]  # kind -> number of DISTINCT identifiers replaced
    failures: list[str]  # detector kinds that fired, never the matched text

    def labelled(self) -> Labelled[str]:
        """The only route from a result to a usable payload -- and it refuses when
        verification failed, so 'forgot to check the flag' is unrepresentable."""
        if not self.verified:
            raise RedactionFailed(
                f"redaction verification failed on {self.failures}; this text is NOT "
                "redacted. Quarantine the run -- there is no cleaning it up later."
            )
        return Labelled(self.text, Sensitivity.REDACTED)


def _hmac_input(kind: str, original: str, *, standalone: bool = True) -> str:
    """A standalone identifier is keyed on its CANONICAL form, so it shares a surrogate
    across layouts and case. A MERGED span is keyed on its full normalised text: a
    canonical form drops parts (digits-only kept "4111 1111 1111 1111" and lost "a@b.cc"),
    which gave a glued span the standalone card's surrogate -- a false join."""
    return _canonical(kind, original) if standalone else original


def _surrogate(kind: str, original: str, key: bytes, *, standalone: bool = True) -> str:
    material = _hmac_input(kind, original, standalone=standalone)
    digest = hmac.new(key, f"{kind}:{material}".encode(), sha256).hexdigest()[:12]
    return f"[{kind.upper()}:{digest.translate(_HEX_TO_LETTERS)}]"


def redact(payload: Labelled[str], *, key: bytes) -> RedactionResult:
    """Normalise, detect, substitute merged spans to a fixpoint, then verify.

    `key` is required, at least 32 bytes, and comes from BOK_REDACTION_KEY. It is never
    committed and never appears in a fixture or an error message.
    """
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(
            f"redact() requires a key of at least {MIN_KEY_BYTES} bytes: short or empty "
            "keys make surrogates brute-forceable"
        )

    text = _normalise(payload.value)
    seen: dict[str, set[str]] = {}

    for _ in range(_MAX_PASSES):
        spans = _merged_spans(text)
        if not spans:
            break
        parts: list[str] = []
        cursor = 0
        for start, end, kind, standalone in spans:
            original = text[start:end]
            seen.setdefault(kind, set()).add(_hmac_input(kind, original, standalone=standalone))
            surrogate = _surrogate(kind, original, key, standalone=standalone)
            parts += [text[cursor:start], surrogate]
            cursor = end
        text = "".join([*parts, text[cursor:]])

    # VERIFICATION. Re-run every detector, including any substitution skipped. A detector
    # firing on the OUTPUT means an identifier of that class survived.
    failures = sorted(kind for kind, pattern in _DETECTORS.items() if pattern.search(text))

    return RedactionResult(
        text=text,
        verified=not failures,
        surrogate_count={kind: len(values) for kind, values in seen.items()},
        failures=failures,
    )
