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

8. `llm.py`
- optional provider interface with Ollama and OpenAI-compatible backends (stdlib HTTP, http/https only, bounded response size)

9. `summarizer.py`
- optional analyst summary: input sanitizing, untrusted-data prompt layout, output policy, fail-closed fallback

## Request lifecycle

1. Parse incident payload.
2. Normalize into `Incident` model.
3. Compute risk score and severity.
4. Rank playbooks and select best candidate.
5. Produce the deterministic summary and reasoning.
6. Optionally request an LLM summary. It is validated against the output policy and replaced by the deterministic result on any failure. It cannot change severity, score or playbook.
7. Update telemetry counters.
8. Return structured JSON result.

## Operational notes

- Metrics are exported in Prometheus text format.
- Container stack includes API + Prometheus.
- The LLM summarizer is off by default. Without it there is no external dependency and no secret.
- LLM calls add latency to each request (default timeout 30 seconds). Run with a local model or a short timeout for high-volume ingestion.
