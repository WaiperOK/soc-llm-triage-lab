# Architecture

## System intent

Provide deterministic and explainable SOC triage behavior while remaining fully local and testable.

## Core modules

1. `models.py`
- incident/playbook/triage data contracts

2. `scoring.py`
- weighted risk scoring from asset criticality, source confidence, and threat terms

3. `retrieval.py`
- term overlap ranking with IDF weighting and tag boosts

4. `triage.py`
- orchestrates scoring + retrieval into a stable `TriageResult`

5. `evaluator.py`
- offline quality checks for severity and top-playbook accuracy

6. `service.py`
- service wrapper and telemetry counters

7. `api.py`
- HTTP control surface: `/v1/triage`, `/healthz`, `/metrics`

## Request lifecycle

1. Parse incident payload.
2. Normalize into `Incident` model.
3. Compute risk score and severity.
4. Rank playbooks and select best candidate.
5. Produce summary and reasoning.
6. Update telemetry counters.
7. Return structured JSON result.

## Operational notes

- Metrics are exported in Prometheus text format.
- Container stack includes API + Prometheus.
- No external LLM or secret dependency required for local demo reliability.
