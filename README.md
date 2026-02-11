# soc-llm-triage-lab

SOC incident triage engine with retrieval-assisted response planning.

## Architecture Intent

Python package provides deterministic retrieval/ranking and rule-based risk escalation. The vertical slice emulates an LLM copilot pipeline without external API dependency.

## Implemented Vertical Slice

- Deterministic core decision engine
- Small API/CLI surface for integration
- Unit tests for regression safety
- CI workflow for every push/PR

## Quickstart

```bash
python -m soc_llm_triage.cli --incident incident.json
```

## Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests
```
