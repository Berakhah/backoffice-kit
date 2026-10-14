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


# Separators the digit detectors accept BETWEEN digits, after normalisation: exactly one
# ASCII space, hyphen or dot. Every Unicode space (Zs) and dash (Pd, U+2212) has already
# been mapped onto these, and format characters (Cf: zero-width space, soft hyphen, word
# joiner, BOM...) removed, so the set is small and explicit. Tabs and newlines are NOT
# separators.
_SEP = r"[ .\-]"

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
    # Compact (NL91ABNA0417164300) or grouped in fours with single spaces
    # (GB82 WEST 1234 5698 7654 32). Upper-case country code only. No left boundary at
    # all, and scanned for overlapping matches (_OVERLAPPING): "a@a.testGB68...",
    # "...0100GB00 0AAA..." and "...AAAAGB00 TTZO ..." must all still yield an IBAN match.
    # Compact: 11-128 characters with no trailing guard -- longer than the IBAN maximum of
    # 30 because two IBANs glued together are one token, and unguarded so a token longer
    # than 128 is consumed in bites rather than matched only at its end (with a guard,
    # "GB12GB12..." verification failed closed). Spaced: guarded, so the match never ends
    # half-way through a group. The cost is over-redaction of long upper-case codes that
    # contain two letters followed by two digits -- the safe direction.
    "iban": re.compile(
        r"[A-Z]{2}\d{2}"
        r"(?:[A-Z0-9]{11,128}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?(?![A-Z0-9]))"
    ),
    # Optional "+CC", then "(ddd)" or "ddd", then ddd and dddd. Without parentheses the two
    # separators must AGREE (backreference): otherwise a Diners card "3056 930902 5904"
    # contains the phone-shaped "930902 5904" -- still redacted whole by the merge, but
    # LABELLED phone whenever that match is the longer one.
    "phone": re.compile(
        rf"(?:\+\d{{1,3}}{_SEP}?)?"
        rf"(?:\(\d{{3}}\){_SEP}?\d{{3}}{_SEP}?\d{{4}}|\d{{3}}({_SEP}?)\d{{3}}\1\d{{4}})"
    ),
    # 20+ digits with optional single separators. Without it a 20-digit run, or a spaced
    # run longer than 19, left an unredacted tail.
    "digit_run": re.compile(rf"\d(?:{_SEP}?\d){{19,}}"),
    "card": re.compile(rf"\d(?:{_SEP}?\d){{12,18}}"),
    # US EIN (12-3456789) and SSN/ITIN (123-45-6789) shapes, hyphenated only.
    "tax_id": re.compile(r"\d{2}-\d{7}|\d{3}-\d{2}-\d{4}"),
    "routing": re.compile(r"\d{9}"),
    # 8-12 contiguous digits, so with `card` (13-19) and `digit_run` (20+) EVERY contiguous
    # run of 8 or more digits is redacted. An isolated 11- or 12-digit run used to match
    # nothing at all. On a 9- or 10-digit tie `routing` / `phone` keep the label by rank.
    "account": re.compile(r"\d{8,12}"),
}

# Detectors scanned for OVERLAPPING matches (a match may start inside another match of
# the same detector). A compact IBAN's [A-Z0-9] run swallows the start of an IBAN glued
# after it ("...AAAA000000000GB00 ZDPK ..."), and a non-overlapping scan resumes only
# after the first match, orphaning the second IBAN's groups. Bounded patterns only:
# the cost is one attempt per start position, at most 128 characters each.
_OVERLAPPING: dict[str, re.Pattern[str]] = {
    kind: re.compile(rf"(?=({_DETECTORS[kind].pattern}))") for kind in ("iban",)
}

# Substitution can expose a new match (a surrogate's ']' newly satisfies the IBAN's
# "not after an upper-case letter" lookbehind), so detect+substitute repeats until
# nothing more is found.
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


def _normalise(text: str) -> str:
    """NFKC (full-width digits -> ASCII), every Unicode space -> ' ', every dash and the
    minus sign -> '-', format characters (zero-width etc.) removed.

    The redacted OUTPUT is this normalised text, and surrogates are computed on the
    normalised identifier, so '4111<NBSP>1111...' and '4111 1111...' share a surrogate.
    """
    out: list[str] = []
    for ch in unicodedata.normalize("NFKC", text):
        category = unicodedata.category(ch)
        if category == "Cf":
            continue
        if category == "Zs":
            out.append(" ")
        elif category == "Pd" or ch == _MINUS_SIGN:
            out.append("-")
        else:
            out.append(ch)
    return "".join(out)


def _merged_spans(text: str) -> list[tuple[int, int, str]]:
    """Every detector's matches over the same text; overlapping matches merged.

    Each merged span is labelled by its longest constituent match (earlier detector on a
    tie), so an IBAN containing a phone-shaped tail is one IBAN, not a residue.
    """
    found: list[tuple[int, int, int, str]] = []
    for rank, (kind, pattern) in enumerate(_DETECTORS.items()):
        if kind in _OVERLAPPING:
            matches = _OVERLAPPING[kind].finditer(text)
            found.extend((m.start(1), m.end(1), rank, kind) for m in matches)
        else:
            found.extend((m.start(), m.end(), rank, kind) for m in pattern.finditer(text))
    found.sort()

    merged: list[tuple[int, int, str, bool]] = []  # (start, end, label, missed)
    best: tuple[int, int] = (0, 0)  # (length, -rank) of the current span's label
    for start, end, rank, kind in found:
        score = (end - start, -rank)
        missed = bool(_SUBSTITUTION_DISABLED.get(kind))
        if merged and start < merged[-1][1]:
            m_start, m_end, m_kind, m_missed = merged[-1]
            if score > best:
                best, m_kind = score, kind
            merged[-1] = (m_start, max(m_end, end), m_kind, m_missed or missed)
        else:
            best = score
            merged.append((start, end, kind, missed))
    return [(start, end, kind) for start, end, kind, missed in merged if not missed]


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


def _surrogate(kind: str, original: str, key: bytes) -> str:
    digest = hmac.new(key, f"{kind}:{original}".encode(), sha256).hexdigest()[:12]
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
        for start, end, kind in spans:
            original = text[start:end]
            seen.setdefault(kind, set()).add(original)
            parts += [text[cursor:start], _surrogate(kind, original, key)]
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
