"""The boundary's second enforcement point: storage, not the gateway.

The gateway guards what leaves for a provider. This guards what lands on disk.

Errors name kinds, planes, labels and paths -- never payload content. Nothing here logs.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from enum import StrEnum
from pathlib import Path

from bok_core.boundary.redact import RedactionResult, _detected_kinds
from bok_core.boundary.sensitivity import Labelled, Sensitivity, SensitivityViolation


class Plane(StrEnum):
    CLIENT = "CLIENT"  # compose-only, no third-party data processor, ever
    DEMO = "DEMO"  # SYNTHETIC / PUBLIC only; hostable anywhere


def _plane(plane: str) -> Plane:
    """Fail closed: an unknown plane is refused, a member's string value is that member."""
    try:
        return Plane(plane)
    except ValueError:
        raise SensitivityViolation(f"unknown plane {plane!r}; refused") from None


def _sensitivity(label: str) -> Sensitivity:
    """Labelled is a dataclass and validates nothing. Identity checks against a raw
    string 'CLIENT_CONFIDENTIAL' would all be False -- fail open -- so the label is
    coerced to its member first, and anything that is not one is refused."""
    try:
        return Sensitivity(label)
    except ValueError:
        raise SensitivityViolation(f"unknown sensitivity {label!r}; refused") from None


def guard_write(
    path: Path,
    payload: Labelled[bytes],
    plane: Plane,
    *,
    redaction: RedactionResult | None = None,
) -> None:
    """Authorise a write. Raises SensitivityViolation; never writes anything itself.

    Refuses, in order:
      * an unknown plane or sensitivity label, a non-bytes payload, a non-RedactionResult
        `redaction` (fail closed on malformed input);
      * CLIENT_CONFIDENTIAL to any plane that is not CLIENT;
      * REDACTED to any plane that is not CLIENT -- DEMO is SYNTHETIC/PUBLIC only;
      * REDACTED with no RedactionResult -- an unproven redaction is an unredacted one;
      * any payload whose redaction verification did not pass;
      * a RedactionResult attached to a payload not labelled REDACTED (relabelling
        redacted client text PUBLIC would launder it onto DEMO);
      * a REDACTED payload whose bytes are not the result's own text, UTF-8 encoded (a
        verified result for one document vouches for nothing else);
      * a REDACTED payload in which any detector still fires (re-verification: a
        RedactionResult is a plain model and verified=True can be hand-built).
    """
    target = _plane(plane)
    sensitivity = _sensitivity(payload.sensitivity)
    if not isinstance(payload.value, bytes):
        raise TypeError(
            f"guard_write takes a Labelled[bytes]; got {type(payload.value).__name__} for {path}"
        )
    if redaction is not None and not isinstance(redaction, RedactionResult):
        raise TypeError(
            f"redaction must be the RedactionResult returned by redact(); got "
            f"{type(redaction).__name__} for {path}"
        )

    if sensitivity is Sensitivity.CLIENT_CONFIDENTIAL and target is not Plane.CLIENT:
        raise SensitivityViolation(
            f"CLIENT_CONFIDENTIAL refused to plane {target} at {path}. "
            "Only the CLIENT plane is compose-only with no third-party processor."
        )

    # R1: DEMO is declared SYNTHETIC/PUBLIC only and enforced nothing of the kind.
    if sensitivity is Sensitivity.REDACTED and target is not Plane.CLIENT:
        raise SensitivityViolation(
            f"REDACTED refused to plane {target} at {path}. DEMO carries SYNTHETIC and "
            "PUBLIC only; redacted client material stays on the CLIENT plane."
        )

    # R1: `redaction` was optional, so omitting it skipped the check entirely. For a
    # REDACTED payload the proof is the whole point.
    if sensitivity is Sensitivity.REDACTED and redaction is None:
        raise SensitivityViolation(
            f"refused write to {path}: REDACTED payload with no RedactionResult. Pass the "
            "result of redact() -- an unproven redaction is an unredacted one."
        )

    if redaction is None:
        return

    if not redaction.verified:
        raise SensitivityViolation(
            f"refused write to {path}: redaction verification failed on "
            f"{list(redaction.failures)}. Quarantine the run; do not write and clean up later."
        )

    if sensitivity is not Sensitivity.REDACTED:
        raise SensitivityViolation(
            f"refused write to {path}: a RedactionResult accompanies only a REDACTED "
            f"payload, and this one is labelled {sensitivity}."
        )

    if payload.value != redaction.text.encode("utf-8"):
        raise SensitivityViolation(
            f"refused write to {path}: the REDACTED payload is not the text of the "
            "RedactionResult supplied with it. Write result.labelled(), encoded as UTF-8."
        )

    survived = _detected_kinds(redaction.text)
    if survived:
        raise SensitivityViolation(
            f"refused write to {path}: redaction re-verification failed on {survived}; the "
            "result claims verified=True but detectors still fire. Quarantine the run."
        )


def write_guarded(
    path: Path,
    payload: Labelled[bytes],
    plane: Plane,
    *,
    redaction: RedactionResult | None = None,
) -> None:
    """Authorise, then write, atomically. PREFER THIS over the bare guard.

    R1: guard_write() authorises and returns, and nothing obliges a caller to have called
    it -- which makes it a convention, not a boundary. This is the path consumers use.
    The bare guard remains for streamed writes the library cannot perform itself, and the
    template ships `test_no_unguarded_writes` to AST-scan for everything else.

    Atomic: the bytes go to a uniquely named temporary file in the target's directory
    (mode 0600 where the OS honours it), are flushed and fsynced, then os.replace()d over
    the target. A crash or a failed replace never leaves half an evidence file, and the
    temporary file is removed on any failure.
    """
    guard_write(path, payload, plane, redaction=redaction)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".partial")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload.value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
