from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .models import Incident, Playbook
from .triage import triage_incident


@dataclass(frozen=True)
class EvalCase:
    incident: Incident
    expected_severity: str
    expected_playbook: str


@dataclass(frozen=True)
class EvalResult:
    total: int
    severity_accuracy: float
    playbook_top1_accuracy: float


def evaluate(cases: Iterable[EvalCase], playbooks: list[Playbook]) -> EvalResult:
    case_list = list(cases)
    if not case_list:
        return EvalResult(total=0, severity_accuracy=0.0, playbook_top1_accuracy=0.0)

    sev_hits = 0
    pb_hits = 0
    for c in case_list:
        out = triage_incident(c.incident, playbooks)
        if out.severity == c.expected_severity:
            sev_hits += 1
        if out.recommended_playbook == c.expected_playbook:
            pb_hits += 1

    total = len(case_list)
    return EvalResult(
        total=total,
        severity_accuracy=round(sev_hits / total, 4),
        playbook_top1_accuracy=round(pb_hits / total, 4),
    )
