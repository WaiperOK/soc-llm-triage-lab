from __future__ import annotations

from dataclasses import dataclass

from .retrieval import Playbook, top_playbook


@dataclass(frozen=True)
class Incident:
    title: str
    description: str
    source: str
    asset_criticality: int
    internet_exposed: bool


@dataclass(frozen=True)
class TriageResult:
    severity: str
    score: int
    recommended_playbook: str | None
    analyst_summary: str


def _base_score(incident: Incident) -> int:
    score = incident.asset_criticality * 10
    if incident.internet_exposed:
        score += 20
    text = f"{incident.title} {incident.description}".lower()
    high_risk_terms = ["ransomware", "credential", "exfiltration", "c2", "domain admin"]
    score += sum(8 for t in high_risk_terms if t in text)
    return min(score, 100)


def _severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def triage_incident(incident: Incident, playbooks: list[Playbook]) -> TriageResult:
    score = _base_score(incident)
    sev = _severity(score)
    pb = top_playbook(f"{incident.title} {incident.description}", playbooks)
    summary = (
        f"{sev.upper()} incident from {incident.source}. "
        f"Risk score={score}. "
        f"Focus on containment and evidence integrity."
    )
    return TriageResult(
        severity=sev,
        score=score,
        recommended_playbook=pb.name if pb else None,
        analyst_summary=summary,
    )
