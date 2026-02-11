from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable

from .models import Playbook, RetrievalCandidate

TOKEN_RE = re.compile(r"[a-zA-Z0-9_\-]{3,}")


def _tokenize(text: str) -> list[str]:
    return [m.group(0).lower() for m in TOKEN_RE.finditer(text)]


def _tf(tokens: list[str]) -> Counter[str]:
    return Counter(tokens)


def _idf(playbooks: list[Playbook]) -> dict[str, float]:
    docs = [set(_tokenize(pb.text + " " + " ".join(pb.tags))) for pb in playbooks]
    total = len(docs)
    freq: Counter[str] = Counter()
    for d in docs:
        freq.update(d)
    return {term: math.log((total + 1) / (1 + df)) + 1.0 for term, df in freq.items()}


def rank_playbooks(incident_text: str, incident_tags: Iterable[str], playbooks: Iterable[Playbook]) -> list[RetrievalCandidate]:
    playbook_list = list(playbooks)
    if not playbook_list:
        return []

    idf = _idf(playbook_list)
    inc_tokens = _tokenize(incident_text)
    inc_tf = _tf(inc_tokens)
    inc_set = set(inc_tokens)
    tag_set = {t.lower() for t in incident_tags}

    out: list[RetrievalCandidate] = []
    for pb in playbook_list:
        pb_tokens = _tokenize(pb.text + " " + " ".join(pb.tags))
        pb_tf = _tf(pb_tokens)
        pb_set = set(pb_tokens)

        matched = sorted(inc_set.intersection(pb_set))
        lexical = 0.0
        for term in matched:
            lexical += min(inc_tf[term], pb_tf[term]) * idf.get(term, 1.0)

        # Tag overlap has stronger semantics than free text overlap.
        tag_boost = float(len(tag_set.intersection(set(pb.tags))) * 2)
        score = lexical + tag_boost

        out.append(
            RetrievalCandidate(
                playbook=pb,
                score=score,
                matched_terms=tuple(matched[:10]),
            )
        )

    out.sort(key=lambda x: x.score, reverse=True)
    return out
