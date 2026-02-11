from __future__ import annotations

from .models import Incident, Playbook, TriageResult
from .retrieval import rank_playbooks
from .scoring import confidence_for_score, score_incident, severity_for_score


def triage_incident(incident: Incident, playbooks: list[Playbook], top_k: int = 3) -> TriageResult:
    score, reasons = score_incident(incident)
    severity = severity_for_score(score)

    candidates = rank_playbooks(
        incident_text=f"{incident.title} {incident.description}",
        incident_tags=incident.tags,
        playbooks=playbooks,
    )

    primary = candidates[0] if candidates else None
    confidence = confidence_for_score(score, primary.score if primary else 0.0)

    analyst_summary = (
        f"{severity.upper()} incident ({incident.source}) for criticality={incident.asset_criticality}. "
        f"Score={score}, confidence={confidence}. "
        "Contain first, preserve evidence, then scope impact."
    )

    return TriageResult(
        severity=severity,
        score=score,
        confidence=confidence,
        recommended_playbook=primary.playbook.name if primary else None,
        top_candidates=tuple(c.playbook.name for c in candidates[:top_k]),
        analyst_summary=analyst_summary,
        reasoning=tuple(reasons),
    )
