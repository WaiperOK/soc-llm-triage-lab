# Changelog

## Unreleased

- added optional LLM summarizer with Ollama and OpenAI-compatible providers (off by default)
- model output is advisory only: severity, score, confidence and playbook stay deterministic
- added input sanitizing, untrusted-data prompt layout, output policy and fail-closed fallback
- added `llm_summary`, `summary_source` and `llm_fallback_reason` to the triage result
- added LLM metrics (`soc_triage_llm_requests_total`, `soc_triage_llm_fallback_total`)
- added `--llm-provider`, `--llm-model`, `--llm-url` CLI flags and `SOC_LLM_*` environment variables
- added prompt-injection example and tests
- updated threat model for LLM risks

## v0.2.0 - 2026-02-11

- expanded triage core with scoring/retrieval/evaluation modules
- added HTTP API (`/v1/triage`, `/healthz`, `/metrics`)
- added telemetry counters and Prometheus integration
- added Dockerfile, Compose stack, and Makefile
- expanded test suite with API integration coverage
