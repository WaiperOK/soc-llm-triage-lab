from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock

from .models import Incident, Playbook, TriageResult
from .summarizer import LLMSummarizer
from .triage import triage_incident


@dataclass
class Telemetry:
    requests_total: int = 0
    requests_failed: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    llm_requests: int = 0
    llm_fallbacks: dict[str, int] = field(default_factory=dict)


class TriageService:
    def __init__(self, playbooks: list[Playbook], summarizer: LLMSummarizer | None = None) -> None:
        self._playbooks = list(playbooks)
        self._summarizer = summarizer
        self._telemetry = Telemetry()
        self._mu = Lock()

    def triage(self, incident: Incident) -> TriageResult:
        with self._mu:
            self._telemetry.requests_total += 1

        try:
            result = triage_incident(incident, self._playbooks, summarizer=self._summarizer)
        except Exception:
            with self._mu:
                self._telemetry.requests_failed += 1
            raise

        with self._mu:
            self._telemetry.severity_counts[result.severity] = self._telemetry.severity_counts.get(result.severity, 0) + 1
            if self._summarizer is not None:
                self._telemetry.llm_requests += 1
                if result.llm_fallback_reason:
                    reason = result.llm_fallback_reason
                    self._telemetry.llm_fallbacks[reason] = self._telemetry.llm_fallbacks.get(reason, 0) + 1
        return result

    def metrics_text(self) -> str:
        with self._mu:
            lines = [
                "# HELP soc_triage_requests_total Total triage requests.",
                "# TYPE soc_triage_requests_total counter",
                f"soc_triage_requests_total {self._telemetry.requests_total}",
                "# HELP soc_triage_requests_failed_total Failed triage requests.",
                "# TYPE soc_triage_requests_failed_total counter",
                f"soc_triage_requests_failed_total {self._telemetry.requests_failed}",
                "# HELP soc_triage_severity_total Severity distribution.",
                "# TYPE soc_triage_severity_total counter",
            ]
            for sev in sorted(self._telemetry.severity_counts):
                lines.append(f'soc_triage_severity_total{{severity="{sev}"}} {self._telemetry.severity_counts[sev]}')
            if self._summarizer is not None:
                lines += [
                    "# HELP soc_triage_llm_requests_total Triage requests that attempted an LLM summary.",
                    "# TYPE soc_triage_llm_requests_total counter",
                    f"soc_triage_llm_requests_total {self._telemetry.llm_requests}",
                    "# HELP soc_triage_llm_fallback_total LLM summaries replaced by the deterministic summary, by reason.",
                    "# TYPE soc_triage_llm_fallback_total counter",
                ]
                for reason in sorted(self._telemetry.llm_fallbacks):
                    lines.append(f'soc_triage_llm_fallback_total{{reason="{reason}"}} {self._telemetry.llm_fallbacks[reason]}')
            return "\n".join(lines) + "\n"
