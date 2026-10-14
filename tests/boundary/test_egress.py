import logging
import os
from pathlib import Path

import pytest

from bok_core.boundary.egress import Plane, guard_write, write_guarded
from bok_core.boundary.redact import RedactionResult, redact
from bok_core.boundary.sensitivity import Labelled, Sensitivity, SensitivityViolation

KEY = b"test-key; real keys come from BOK_REDACTION_KEY and are never committed"

# A distinctive value that must never appear in any error, repr or log line.
CONTENT = "acct 98765432 for ana.secret@client.test"
CONTENT_WORDS = ("98765432", "ana.secret", "client.test")


def _redacted(text: str = CONTENT) -> tuple[Labelled[bytes], RedactionResult]:
    """The only honest way to get a REDACTED payload: redact(), then its own bytes."""
    result = redact(Labelled(text, Sensitivity.CLIENT_CONFIDENTIAL), key=KEY)
    assert result.verified is True
    return Labelled(result.text.encode("utf-8"), Sensitivity.REDACTED), result


def _forged(text: str, *, verified: bool, failures: list[str]) -> RedactionResult:
    return RedactionResult(text=text, verified=verified, surrogate_count={}, failures=failures)


def _assert_silent(exc: BaseException) -> None:
    for rendered in (str(exc), repr(exc)):
        for word in CONTENT_WORDS:
            assert word not in rendered, rendered


# --- the brief's tests (adapted where noted) ---------------------------------------------


def test_client_confidential_refused_to_a_demo_plane(tmp_path: Path) -> None:
    with pytest.raises(SensitivityViolation, match="DEMO") as info:
        guard_write(
            tmp_path / "shot.png",
            Labelled(CONTENT.encode(), Sensitivity.CLIENT_CONFIDENTIAL),
            Plane.DEMO,
        )
    assert "CLIENT_CONFIDENTIAL" in str(info.value)
    _assert_silent(info.value)


def test_client_confidential_allowed_on_the_client_plane(tmp_path: Path) -> None:
    guard_write(
        tmp_path / "shot.png", Labelled(b"portal", Sensitivity.CLIENT_CONFIDENTIAL), Plane.CLIENT
    )


def test_unverified_redaction_is_never_written(tmp_path: Path) -> None:
    """selector-drift: un-redacted evidence is never written to be cleaned up later.
    There is no later -- the run quarantines instead."""
    failed = _forged(CONTENT, verified=False, failures=["account", "email"])
    payload = Labelled(CONTENT.encode(), Sensitivity.REDACTED)
    with pytest.raises(SensitivityViolation, match="redaction verification failed") as info:
        guard_write(tmp_path / "dom.html", payload, Plane.CLIENT, redaction=failed)
    assert "account" in str(info.value)  # kinds only
    _assert_silent(info.value)


def test_an_unverified_redaction_is_refused_whatever_the_payload_label(tmp_path: Path) -> None:
    """Contract: 'any payload whose redaction verification did not pass'."""
    failed = _forged(CONTENT, verified=False, failures=["account"])
    for sensitivity in Sensitivity:
        with pytest.raises(SensitivityViolation) as info:
            guard_write(tmp_path / "x", Labelled(b"x", sensitivity), Plane.CLIENT, redaction=failed)
        _assert_silent(info.value)


def test_verified_redaction_passes(tmp_path: Path) -> None:
    """ADAPTED: the brief paired b"x" with an unrelated result. The payload must now be
    the result's own text (see test_a_redacted_payload_must_be_the_results_own_text)."""
    payload, ok = _redacted()
    guard_write(tmp_path / "dom.html", payload, Plane.CLIENT, redaction=ok)


def test_redacted_is_refused_to_the_demo_plane(tmp_path: Path) -> None:
    """R1: the Plane enum's own comment says DEMO is 'SYNTHETIC / PUBLIC only' and the
    guard enforced nothing of the sort -- REDACTED sailed straight through. A redacted
    client document is still derived from a client document; DEMO is hostable anywhere."""
    payload, ok = _redacted()
    with pytest.raises(SensitivityViolation, match="DEMO") as info:
        guard_write(tmp_path / "e.html", payload, Plane.DEMO, redaction=ok)
    assert "REDACTED" in str(info.value)


def test_redacted_without_proof_of_redaction_is_refused(tmp_path: Path) -> None:
    """R1: `redaction` was an OPTIONAL argument, so selector-drift's whole requirement --
    capture, redact, verify, store, quarantine on failure -- was opt-in. Omitting the
    argument skipped the check silently, which is the one thing a boundary may not do."""
    with pytest.raises(SensitivityViolation, match="no RedactionResult") as info:
        guard_write(
            tmp_path / "e.html", Labelled(CONTENT.encode(), Sensitivity.REDACTED), Plane.CLIENT
        )
    _assert_silent(info.value)


def test_write_guarded_checks_and_then_actually_writes(tmp_path: Path) -> None:
    """R1: a guard that only authorises is advisory -- nothing obliges a caller to have
    called it, which makes it a lint rule rather than a boundary. write_guarded() is the
    path consumers use."""
    target = tmp_path / "ok.bin"
    write_guarded(target, Labelled(b"payload", Sensitivity.PUBLIC), Plane.DEMO)
    assert target.read_bytes() == b"payload"

    with pytest.raises(SensitivityViolation):
        write_guarded(
            tmp_path / "no.bin", Labelled(b"x", Sensitivity.CLIENT_CONFIDENTIAL), Plane.DEMO
        )
    assert not (tmp_path / "no.bin").exists()


def test_guard_does_not_itself_write(tmp_path: Path) -> None:
    """It authorises; the caller writes. A guard that also writes is one refactor
    away from a path that writes without asking."""
    target = tmp_path / "nothing.bin"
    guard_write(target, Labelled(b"x", Sensitivity.PUBLIC), Plane.DEMO)
    assert not target.exists()
    assert list(tmp_path.iterdir()) == []


# --- binding: a REDACTED payload only through a verified RedactionResult -----------------


def test_a_redacted_payload_must_be_the_results_own_text(tmp_path: Path) -> None:
    """A verified result for one document must not vouch for different bytes: otherwise
    raw text labelled REDACTED plus any verified result is a write of unredacted data."""
    _, ok = _redacted()
    raw = Labelled(CONTENT.encode(), Sensitivity.REDACTED)
    with pytest.raises(SensitivityViolation, match="not the text of the RedactionResult") as info:
        guard_write(tmp_path / "dom.html", raw, Plane.CLIENT, redaction=ok)
    _assert_silent(info.value)


def test_a_forged_verified_flag_is_re_verified(tmp_path: Path) -> None:
    """RedactionResult is a plain model: anyone can construct verified=True. The guard
    re-runs every detector over the text it is asked to write, so a forged flag over
    text that still holds an identifier is refused."""
    forged = _forged(CONTENT, verified=True, failures=[])
    payload = Labelled(CONTENT.encode(), Sensitivity.REDACTED)
    with pytest.raises(SensitivityViolation, match="re-verification failed") as info:
        guard_write(tmp_path / "dom.html", payload, Plane.CLIENT, redaction=forged)
    assert "account" in str(info.value) and "email" in str(info.value)
    _assert_silent(info.value)


def test_a_redaction_attached_to_a_non_redacted_payload_is_refused(tmp_path: Path) -> None:
    """Redacted text relabelled PUBLIC would launder client material onto DEMO."""
    payload, ok = _redacted()
    for sensitivity in (Sensitivity.PUBLIC, Sensitivity.SYNTHETIC):
        relabelled = Labelled(payload.value, sensitivity)
        with pytest.raises(SensitivityViolation, match="only a REDACTED payload"):
            guard_write(tmp_path / "e.html", relabelled, Plane.DEMO, redaction=ok)


def test_labelled_from_a_verified_result_is_the_supported_route(tmp_path: Path) -> None:
    """RedactionResult.labelled() raises unless verified; its text, encoded, is the payload."""
    result = redact(Labelled(CONTENT, Sensitivity.CLIENT_CONFIDENTIAL), key=KEY)
    text = result.labelled()
    payload = Labelled(text.value.encode("utf-8"), text.sensitivity)
    target = tmp_path / "dom.json"
    write_guarded(target, payload, Plane.CLIENT, redaction=result)
    assert target.read_text(encoding="utf-8") == result.text
    for word in CONTENT_WORDS:
        assert word not in target.read_text(encoding="utf-8")


# --- fail closed on malformed input -------------------------------------------------------


def test_an_unknown_sensitivity_label_is_refused(tmp_path: Path) -> None:
    """Labelled is a dataclass and validates nothing. A raw string that IS a member value
    is read as that member (so 'CLIENT_CONFIDENTIAL' as a str is still refused to DEMO);
    anything else is refused outright rather than slipping past identity checks."""
    as_str = Labelled(b"x", "CLIENT_CONFIDENTIAL")  # type: ignore[arg-type]
    with pytest.raises(SensitivityViolation, match="DEMO"):
        guard_write(tmp_path / "x", as_str, Plane.DEMO)
    bogus = Labelled(b"x", "TOP_SECRET")  # type: ignore[arg-type]
    with pytest.raises(SensitivityViolation, match="unknown sensitivity"):
        guard_write(tmp_path / "x", bogus, Plane.CLIENT)


def test_an_unknown_plane_is_refused(tmp_path: Path) -> None:
    with pytest.raises(SensitivityViolation, match="unknown plane"):
        guard_write(tmp_path / "x", Labelled(b"x", Sensitivity.PUBLIC), "S3")  # type: ignore[arg-type]
    # A plane given as its string value is that plane.
    guard_write(tmp_path / "x", Labelled(b"x", Sensitivity.PUBLIC), "DEMO")  # type: ignore[arg-type]


def test_a_payload_that_is_not_bytes_is_refused(tmp_path: Path) -> None:
    """A Labelled[Path] or a handle would be written as its repr, or not at all."""
    with pytest.raises(TypeError, match="bytes"):
        guard_write(
            tmp_path / "x",
            Labelled(Path("a.pdf"), Sensitivity.PUBLIC),  # type: ignore[arg-type]
            Plane.DEMO,
        )


def test_a_non_result_redaction_is_refused(tmp_path: Path) -> None:
    class Lookalike:
        verified = True
        text = "x"
        failures: list[str] = []  # noqa: RUF012

    with pytest.raises(TypeError, match="RedactionResult"):
        guard_write(
            tmp_path / "x",
            Labelled(b"x", Sensitivity.REDACTED),
            Plane.CLIENT,
            redaction=Lookalike(),  # type: ignore[arg-type]
        )


# --- the whole decision table, so every refusal is shown reachable AND necessary ----------


def _expected(sensitivity: Sensitivity, plane: Plane, proof: str) -> str | None:
    """An independent statement of the rules: the refusal message fragment, or None."""
    if sensitivity is Sensitivity.CLIENT_CONFIDENTIAL and plane is Plane.DEMO:
        return "CLIENT_CONFIDENTIAL"
    if sensitivity is Sensitivity.REDACTED and plane is Plane.DEMO:
        return "REDACTED refused"
    if sensitivity is Sensitivity.REDACTED and proof == "none":
        return "no RedactionResult"
    if proof == "failed":
        return "redaction verification failed"
    if proof == "ok" and sensitivity is not Sensitivity.REDACTED:
        return "only a REDACTED payload"
    return None


@pytest.mark.parametrize("sensitivity", list(Sensitivity))
@pytest.mark.parametrize("plane", list(Plane))
@pytest.mark.parametrize("proof", ["none", "ok", "failed"])
def test_every_cell_of_the_decision_table(
    tmp_path: Path, sensitivity: Sensitivity, plane: Plane, proof: str
) -> None:
    redacted, ok = _redacted()
    failed = _forged(ok.text, verified=False, failures=["account"])
    redaction = {"none": None, "ok": ok, "failed": failed}[proof]
    payload = Labelled(redacted.value, sensitivity)
    target = tmp_path / "out.bin"
    expected = _expected(sensitivity, plane, proof)
    if expected is None:
        guard_write(target, payload, plane, redaction=redaction)
        write_guarded(target, payload, plane, redaction=redaction)
        assert target.read_bytes() == payload.value
    else:
        for call in (guard_write, write_guarded):
            with pytest.raises(SensitivityViolation, match=expected):
                call(target, payload, plane, redaction=redaction)
        assert not target.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == (["out.bin"] if expected is None else [])


# --- no echo, no logging -----------------------------------------------------------------


def test_refusals_log_nothing(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    failed = _forged(CONTENT, verified=False, failures=["account"])
    attempts = [
        (Labelled(CONTENT.encode(), Sensitivity.CLIENT_CONFIDENTIAL), Plane.DEMO, None),
        (Labelled(CONTENT.encode(), Sensitivity.REDACTED), Plane.CLIENT, None),
        (Labelled(CONTENT.encode(), Sensitivity.REDACTED), Plane.CLIENT, failed),
    ]
    for payload, plane, redaction in attempts:
        with pytest.raises(SensitivityViolation) as info:
            write_guarded(tmp_path / "x", payload, plane, redaction=redaction)
        _assert_silent(info.value)
    assert caplog.records == []


# --- atomic write ------------------------------------------------------------------------


def test_a_failed_write_leaves_neither_the_target_nor_a_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "evidence.html"
    target.write_bytes(b"previous version")

    def boom(src: object, dst: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        write_guarded(target, Labelled(b"new version", Sensitivity.PUBLIC), Plane.DEMO)
    assert target.read_bytes() == b"previous version"  # never half-written
    assert [p.name for p in tmp_path.iterdir()] == ["evidence.html"]


def test_write_guarded_replaces_an_existing_file_whole(tmp_path: Path) -> None:
    target = tmp_path / "evidence.html"
    target.write_bytes(b"a much longer previous version of the evidence file")
    write_guarded(target, Labelled(b"short", Sensitivity.SYNTHETIC), Plane.DEMO)
    assert target.read_bytes() == b"short"
    assert [p.name for p in tmp_path.iterdir()] == ["evidence.html"]


def test_write_guarded_does_not_clobber_a_sibling_partial_name(tmp_path: Path) -> None:
    """The brief's temp name was a fixed '<name>.partial': it overwrote any file of that
    name and two concurrent writers raced on it. The temp file is now unique."""
    target = tmp_path / "e.html"
    sibling = tmp_path / "e.html.partial"
    sibling.write_bytes(b"someone else's file")
    write_guarded(target, Labelled(b"x", Sensitivity.PUBLIC), Plane.DEMO)
    assert sibling.read_bytes() == b"someone else's file"
    assert target.read_bytes() == b"x"
