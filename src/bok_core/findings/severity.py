"""The shared severity ladder. Never encoded in colour alone at the UI layer."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
