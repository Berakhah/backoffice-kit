"""Detect -> keyed stable surrogate -> VERIFY BY RE-DETECTING.

R1 rewrote this module. Three things were wrong, and each was the kind of wrong that
ships green:

1. The verification pass could not fail. It searched the output for the very strings it
   had just replaced, so absent a deliberately injected leak the answer was always "all
   clear". The one control 00 section 4.2 singles out as needing proof was decorative.
   Verification now RE-RUNS EVERY DETECTOR over the output, which is what catches the
   real failure mode: a match the first pass split, overlapped, or had no pattern for.

2. `_force_leak=` was a production keyword argument whose entire function was to write a
   raw secret into a redacted document -- it existed so the tautology above had something
   to catch. Both are gone. The test simulates a MISSED detection instead, which is a
   real failure rather than a self-inflicted one.

3. Surrogates were sha256(identifier)[:8] -- an unkeyed hash of a low-entropy value. The
   whole 9-digit routing-number space brute-forces in seconds, and so does any phone
   number, so a "redacted" document was a lookup table. Surrogates are now HMAC-keyed.

And the result object no longer carries the identifiers it removed: see RedactionResult.
"""

from __future__ import annotations

import hmac
import re
from hashlib import sha256

from pydantic import BaseModel, ConfigDict

from bok_core.boundary.sensitivity import Labelled, Sensitivity

# What this module claims to detect, and what it does not. 00 section 4.2 names six
# classes. Both tuples are asserted by a test and declared in docs/methodology.md (a test
# keeps the two in step), so the gap is a declared limitation rather than a silent hole.
COVERED = ("email", "phone", "iban", "card", "routing", "tax_id", "account")
NOT_COVERED = ("person_name", "address")


class RedactionFailed(Exception):
    """Verification did not pass. This text is not safe to treat as REDACTED."""


# Person names and addresses need local NER (spaCy/GLiNER) and land in week 5, driven by
# ledger-sense's real corpus. Regex reaches neither class, and shipping a weak NER now
# would be worse than naming the gap -- but the gap IS named, in COVERED / NOT_COVERED and
# in methodology.md. Until then, a document containing a person's name is not REDACTED;
# it is CLIENT_CONFIDENTIAL.
#
# Order matters: the longest-span classes run first so that a card number is consumed
# before the 8- and 9-digit runs inside it can match.
_DETECTORS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
    # R1: was r"\b\d{3}[-.\s]\d{4}\b" -- misses every international and parenthesised
    # form, and fires inside ordinary numbers.
    "phone": re.compile(
        r"(?<!\d)(?:\+\d{1,3}[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)"
    ),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    # 13-19 digits, single spaces or hyphens allowed BETWEEN digits only, so the match
    # never swallows the separator that follows the number.
    "card": re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)"),
    "routing": re.compile(r"(?<!\d)\d{9}(?!\d)"),
    # R1: 00 section 4.2 names tax ids explicitly and the plan shipped no detector.
    # US EIN (12-3456789) and SSN/ITIN (123-45-6789) shapes only.
    "tax_id": re.compile(r"(?<!\d)\d{2}-\d{7}(?!\d)|(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
    "account": re.compile(r"(?<!\d)\d{8}(?!\d)"),
}

# Test seam. A kind set here skips SUBSTITUTION while DETECTION stays on, which is how
# the verification pass is exercised against a genuine miss rather than a planted leak.
_SUBSTITUTION_DISABLED: dict[str, bool] = {}

# Surrogate digests are rendered in a DIGIT-FREE alphabet. A plain hex digest contains a
# run of 8-10 decimal digits a few percent of the time, which would (a) be re-substituted
# by a later detector inside an earlier surrogate and (b) make verification fail on a
# CORRECT redaction -- a flaky boundary gets muted, which is worse than none. Same 4 bits
# per character as hex, so the entropy is unchanged.
_HEX_TO_LETTERS = str.maketrans("0123456789abcdef", "abcdefghijklmnop")


class RedactionResult(BaseModel):
    """R1: `surrogates: dict[original -> surrogate]` is gone.

    That map was keyed by the ORIGINAL identifier, so this object -- handed back to the
    caller and passed into egress.guard_write() -- carried every piece of PII the
    redactor had just removed. Logging it, caching it or letting it reach a traceback
    re-leaked the document. A caller who genuinely needs the reverse map builds it on the
    CLIENT plane, behind the egress guard, and never returns it across this boundary.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    text: str
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
    """Detect, substitute, then verify by re-detecting.

    `key` is required and comes from BOK_REDACTION_KEY. It is never committed and never
    appears in a fixture. There is deliberately no default: falling back to an unkeyed
    hash would be indistinguishable from the bug this replaced.
    """
    if not key:
        raise ValueError("redact() requires a key: unkeyed surrogates are reversible")

    text = payload.value
    counts: dict[str, int] = {}

    for kind, pattern in _DETECTORS.items():
        if _SUBSTITUTION_DISABLED.get(kind):
            continue
        seen: set[str] = set()

        def _sub(m: re.Match[str], _kind: str = kind, _seen: set[str] = seen) -> str:
            _seen.add(m.group(0))
            return _surrogate(_kind, m.group(0), key)

        text = pattern.sub(_sub, text)
        if seen:
            counts[kind] = len(seen)

    # VERIFICATION. Re-run every detector, including any substitution skipped. A detector
    # firing on the OUTPUT means an identifier of that class survived -- whatever the
    # reason, and the reasons that matter are the ones nobody anticipated.
    failures = sorted(kind for kind, pattern in _DETECTORS.items() if pattern.search(text))

    return RedactionResult(
        text=text, verified=not failures, surrogate_count=counts, failures=failures
    )
