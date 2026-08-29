"""The axes of the data boundary.

Sensitivity answers "who may receive this". Trust answers "is this content hostile".
They are orthogonal: an attacker-authored MCP tool description is PUBLIC and UNTRUSTED.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Generic, TypeVar

T = TypeVar("T")


class Sensitivity(StrEnum):
    """The wire format is the STRING. Ordering is `.rank`, never the member value.

    R1: this was an IntEnum, contradicting INTERFACE-CONTRACT section 1.1. That would put
    integers in the ledger's TEXT column and in every JSON payload the four consumers
    parse. It cannot simply become a plain StrEnum either: StrEnum compares lexically, so
    `PUBLIC < CLIENT_CONFIDENTIAL` is False and every restriction check silently inverts.
    Hence a string value and an explicit rank.
    """

    PUBLIC = "PUBLIC"
    SYNTHETIC = "SYNTHETIC"
    REDACTED = "REDACTED"
    CLIENT_CONFIDENTIAL = "CLIENT_CONFIDENTIAL"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK: dict[Sensitivity, int] = {}  # filled in below, after the class body


class Trust(StrEnum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"


class SensitivityViolation(Exception):
    """Raised when a payload would cross a boundary it may not cross.

    Never downgraded to a warning. See 00 R4.
    """


@dataclass(frozen=True, slots=True)
class Labelled(Generic[T]):
    """A payload carrying its boundary labels.

    Wraps str, bytes, Path or an open handle -- not only prompts. The label must attach
    where a file is opened; attaching it at gateway entry is too late (ledger-sense 4.1.4).

    frozen=True blocks plain attribute assignment (`labelled.sensitivity = PUBLIC`), which
    would otherwise silently downgrade a CLIENT_CONFIDENTIAL payload after the fact. Unlike
    a pydantic model there is no `model_copy` equivalent shipped here, so this closes the
    mutation path completely rather than leaving a residual gap.
    """

    value: T
    sensitivity: Sensitivity
    trust: Trust = Trust.TRUSTED

    @classmethod
    def from_path(
        cls, path: Path, sensitivity: Sensitivity, trust: Trust = Trust.TRUSTED
    ) -> Labelled[bytes]:
        """Read and label in one step, so an unlabelled read is not expressible."""
        return Labelled(path.read_bytes(), sensitivity, trust)

    def __repr__(self) -> str:
        return f"Labelled(<{type(self.value).__name__}>, {self.sensitivity}, {self.trust})"

    __str__ = __repr__  # R1: repr() was guarded, str() was not, and f"{payload}" leaked.


_RANK.update(
    {
        Sensitivity.PUBLIC: 0,
        Sensitivity.SYNTHETIC: 1,
        Sensitivity.REDACTED: 2,
        Sensitivity.CLIENT_CONFIDENTIAL: 3,
    }
)
