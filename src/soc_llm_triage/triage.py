from __future__ import annotations

from .models import Incident, Playbook, TriageResult
from .retrieval import rank_playbooks
from .scoring import confidence_for_score, score_incident, severity_for_score
from .summarizer import LLMSummarizer


def triage_incident(
    incident: Incident,
    playbooks: list[Playbook],
    top_k: int = 3,
    summarizer: LLMSummarizer | None = None,
) -> TriageResult:
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

    playbook_name = primary.playbook.name if primary else None
    llm_summary = None
    summary_source = "deterministic"
    fallback_reason = None
    if summarizer is not None:
        # The model only adds prose. Severity, score and playbook are already fixed above.
        outcome = summarizer.summarize(incident, score, severity, playbook_name, reasons)
        llm_summary, summary_source, fallback_reason = outcome.text, outcome.source, outcome.reason

    return TriageResult(
        severity=severity,
        score=score,
        confidence=confidence,
        recommended_playbook=playbook_name,
        top_candidates=tuple(c.playbook.name for c in candidates[:top_k]),
        analyst_summary=analyst_summary,
        reasoning=tuple(reasons),
        llm_summary=llm_summary,
        summary_source=summary_source,
        llm_fallback_reason=fallback_reason,
    )
