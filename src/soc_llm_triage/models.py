from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Incident:
    title: str
    description: str
    source: str = "unknown"
    asset_criticality: int = 3
    internet_exposed: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Incident":
        return cls(
            title=str(payload["title"]),
            description=str(payload.get("description", "")),
            source=str(payload.get("source", "unknown")),
            asset_criticality=max(1, min(5, int(payload.get("asset_criticality", 3)))),
            internet_exposed=bool(payload.get("internet_exposed", False)),
            tags=tuple(str(t).lower() for t in payload.get("tags", [])),
        )


@dataclass(frozen=True)
class Playbook:
    name: str
    text: str
    tags: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Playbook":
        return cls(
            name=str(payload["name"]),
            text=str(payload.get("text", "")),
            tags=tuple(str(t).lower() for t in payload.get("tags", [])),
        )


@dataclass(frozen=True)
class RetrievalCandidate:
    playbook: Playbook
    score: float
    matched_terms: tuple[str, ...]


@dataclass(frozen=True)
class TriageResult:
    severity: str
    score: int
    confidence: float
    recommended_playbook: str | None
    top_candidates: tuple[str, ...]
    analyst_summary: str
    reasoning: tuple[str, ...]
    llm_summary: str | None = None
    summary_source: str = "deterministic"
    llm_fallback_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["reasoning"] = list(self.reasoning)
        payload["top_candidates"] = list(self.top_candidates)
        return payload
