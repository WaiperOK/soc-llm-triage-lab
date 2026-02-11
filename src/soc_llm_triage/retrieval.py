from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Playbook:
    name: str
    text: str


def score_text_overlap(incident_text: str, playbook_text: str) -> int:
    incident_terms = {x for x in incident_text.lower().split() if len(x) > 3}
    playbook_terms = {x for x in playbook_text.lower().split() if len(x) > 3}
    return len(incident_terms.intersection(playbook_terms))


def top_playbook(incident_text: str, playbooks: Iterable[Playbook]) -> Playbook | None:
    best: Playbook | None = None
    best_score = -1
    for pb in playbooks:
        score = score_text_overlap(incident_text, pb.text)
        if score > best_score:
            best = pb
            best_score = score
    return best
