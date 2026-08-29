"""Where a Claim came from. Seven variants, one per real consumer need."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class BBox(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    x0: float
    y0: float
    x1: float
    y1: float

    @model_validator(mode="after")
    def _ordered(self) -> BBox:
        if self.x1 < self.x0 or self.y1 < self.y0:
            raise ValueError("bbox coordinates must be ordered (x0<=x1, y0<=y1)")
        return self


class _Base(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class FileSource(_Base):
    kind: Literal["file"] = "file"
    path: str
    line: int


class DocumentSource(_Base):
    kind: Literal["document"] = "document"
    path: str
    page: int
    bbox: BBox


class UrlSource(_Base):
    kind: Literal["url"] = "url"
    url: str
    retrieved_at: datetime


class ModelSource(_Base):
    kind: Literal["model"] = "model"
    ledger_call_id: str
    """Foreign key into bok_ledger.call_id. See INTERFACE-CONTRACT 3.4."""


class HumanSource(_Base):
    kind: Literal["human"] = "human"
    who: str
    at: datetime


class RuleSource(_Base):
    kind: Literal["rule"] = "rule"
    authority: str
    citation: str
    confirmed_by: str
    confirmed_at: datetime


class DomSource(_Base):
    kind: Literal["dom"] = "dom"
    snapshot_id: str
    selector: str
    rung: int


Source = Annotated[
    FileSource | DocumentSource | UrlSource | ModelSource | HumanSource | RuleSource | DomSource,
    Field(discriminator="kind"),
]
