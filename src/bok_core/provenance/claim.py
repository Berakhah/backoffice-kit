"""Every number that reaches a user is a Claim, never a bare float."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, field_serializer, model_validator

from bok_core.provenance.source import Source

T = TypeVar("T")


class Method(StrEnum):
    DETERMINISTIC = "DETERMINISTIC"
    MODEL = "MODEL"
    HUMAN = "HUMAN"
    DERIVED = "DERIVED"


class Derivation(StrEnum):
    """How a deterministic fact was obtained. All four are DETERMINISTIC with
    materially different trustworthiness (agent-perimeter B9)."""

    SCHEMA = "SCHEMA"
    DESCRIPTION = "DESCRIPTION"
    PROBE = "PROBE"
    ARTIFACT = "ARTIFACT"


class CalibrationState(StrEnum):
    UNCALIBRATED = "UNCALIBRATED"
    CALIBRATED = "CALIBRATED"


class Calibration(BaseModel):
    """The reliability basis behind a confidence. An object, never a float --
    "synthetic corpus only" must render differently from "400 real labelled fields"."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    state: CalibrationState
    basis: str
    curve_id: str | None = None
    n: int | None = None


class Claim(BaseModel, Generic[T]):
    model_config = ConfigDict(extra="forbid")

    value: T
    source: Source
    method: Method
    derivation: Derivation | None = None
    confidence: float | None = None
    calibration: Calibration | None = None
    observed_at: datetime
    # R1: annotated BARE, and this is load-bearing rather than stylistic. A
    # self-referencing PARAMETRISED field on a generic pydantic model fails at
    # parametrisation time: Claim[Decimal] raises AttributeError: __pydantic_fields__
    # on pydantic 2.13.5, for list[Claim[object]] and list[Claim[Any]] alike, with or
    # without an explicit model_rebuild(). Verified on CPython 3.12, 29 Aug 2026.
    # The bare form is also better semantics: it preserves parent identity through
    # validation and keeps a parent's Decimal a Decimal instead of rebuilding it.
    parents: list[Claim] = []  # type: ignore[type-arg]
    caveat: str | None = None

    @field_serializer("value")
    def _serialise_value(self, v: T) -> object:
        # I5: a Decimal must never reach JSON as a float.
        return str(v) if isinstance(v, Decimal) else v

    @model_validator(mode="after")
    def _invariants(self) -> Claim[T]:
        # I3
        if self.method is Method.DETERMINISTIC and self.confidence is not None:
            raise ValueError("DETERMINISTIC claims carry no confidence -- they are exact or absent")
        # I1. R1: enforced HERE, not only in derive(). An invariant the contract says
        # bok-core enforces cannot live in a helper a caller can route around.
        if self.method is Method.DERIVED and self.confidence is not None:
            known = [p.confidence for p in self.parents if p.confidence is not None]
            if known and self.confidence > min(known) + 1e-9:
                raise ValueError(
                    f"DERIVED confidence {self.confidence} cannot exceed its weakest "
                    f"parent's {min(known)}"
                )
        return self

    def renders_as_fact(self) -> bool:
        """Is this safe to render as a fact rather than as an unverified number?

        A MODEL claim is a fact only when calibrated (00 B10) -- and a DERIVED claim is a
        fact only when EVERY ancestor is one too (I7).

        R1: this previously returned True for any method that was not MODEL, so a single
        derive() hop turned an uncalibrated 0.72 model reading into a fact. That is the
        exact sin 00 exists to correct, and the DoD worked example demonstrates it.
        """
        if self.method is Method.MODEL:
            if self.confidence is None or self.calibration is None:
                return False
            if self.calibration.state is not CalibrationState.CALIBRATED:
                return False
        return all(p.renders_as_fact() for p in self.parents)
