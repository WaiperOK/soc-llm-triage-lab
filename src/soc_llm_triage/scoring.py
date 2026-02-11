from __future__ import annotations

from .models import Incident


KEYWORD_WEIGHTS = {
    "ransomware": 18,
    "exfiltration": 16,
    "credential": 14,
    "domain admin": 14,
    "lateral movement": 12,
    "c2": 12,
    "command-and-control": 12,
    "token theft": 10,
    "impossible travel": 8,
}

SOURCE_WEIGHTS = {
    "edr": 12,
    "siem": 8,
    "identity": 8,
    "waf": 5,
    "mail": 4,
}


def score_incident(incident: Incident) -> tuple[int, list[str]]:
    score = incident.asset_criticality * 10
    reasons = [f"asset_criticality={incident.asset_criticality}"]

    if incident.internet_exposed:
        score += 16
        reasons.append("internet_exposed=true")

    source_weight = SOURCE_WEIGHTS.get(incident.source.lower(), 3)
    score += source_weight
    reasons.append(f"source={incident.source.lower()}(+{source_weight})")

    text = f"{incident.title} {incident.description}".lower()
    for term, weight in KEYWORD_WEIGHTS.items():
        if term in text:
            score += weight
            reasons.append(f"keyword={term}(+{weight})")

    # Keep deterministic cap to simplify policy and reporting.
    bounded = max(0, min(100, score))
    return bounded, reasons


def severity_for_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def confidence_for_score(score: int, retrieval_score: float) -> float:
    # Confidence uses both risk score and retrieval strength.
    conf = (score / 100.0) * 0.7 + min(retrieval_score / 20.0, 1.0) * 0.3
    return round(max(0.05, min(conf, 0.99)), 3)
